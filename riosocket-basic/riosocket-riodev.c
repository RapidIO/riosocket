/*********************************************************************
 *  Copyright of Centaurus Computing - 2016
 * 
 *  This file is part of riosocket-basic.
 * 
 *  riosocket-basic is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *   
 *  riosocket-basic is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with riosocket-basic.  If not, see <http://www.gnu.org/licenses/>.
 *  
 *  *********************************************************************/

//#define DEBUG 1
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

MODULE_AUTHOR("Centaurus Computing");
MODULE_DESCRIPTION("RIOSocket-basic Virtual Network Driver");
MODULE_VERSION("1.01.01");
MODULE_LICENSE("GPL");

unsigned short rio_db=0;
module_param(rio_db, short , S_IRUGO);
MODULE_PARM_DESC(rio_db, "RapidIO doorbell base address");

unsigned long rio_phys_mem=0;
module_param(rio_phys_mem, ulong , S_IRUGO);
MODULE_PARM_DESC(rio_phys_mem, "Physical memory address");
EXPORT_SYMBOL(rio_phys_mem);

unsigned long rio_phys_size=0;
module_param(rio_phys_size, ulong , S_IRUGO);
MODULE_PARM_DESC(rio_phys_size, "Physical memory size");
EXPORT_SYMBOL(rio_phys_size);

unsigned long rio_base_addr = DEFAULT_RIO_BASE;
module_param(rio_base_addr, ulong , S_IRUGO);
MODULE_PARM_DESC(rio_base_addr, "Inbound RaridIO window base address");

unsigned long rio_ibw_size = DEFAULT_IBW_SIZE;
module_param(rio_ibw_size, ulong , S_IRUGO);
MODULE_PARM_DESC(rio_ibw_size, "Inbound mapping window size for each mport");

extern const struct attribute_group *riosocket_drv_attr_groups[];
struct riosocket_driver_params stats;
struct riosocket_network nets[MAX_NETS];

static unsigned long net_table=0;
static void *riosocket_cache=NULL;

static struct rio_device_id riosocket_id_table[] = {
	{RIO_DEVICE(RIO_ANY_ID, RIO_ANY_ID)},
	{ 0, }	/* terminate list */
};

inline static struct rio_mport* rio_get_mport( struct rio_dev *rdev )
{
	return rdev->net->hport;
}

static int is_rionet_capable(unsigned int src_ops, unsigned int dst_ops)
{
	if ((src_ops & RIO_SRC_OPS_READ) &&
		(dst_ops & RIO_SRC_OPS_STREAM_WRITE) &&
		(src_ops & RIO_SRC_OPS_DOORBELL) &&
		(dst_ops & RIO_DST_OPS_DOORBELL))
		return 1;
	else
		return 0;
}

static int dev_is_rionet_capable( struct rio_dev *rdev )
{
	return is_rionet_capable(rdev->src_ops,
		rdev->dst_ops);
}

static void riosocket_tx_cb( void *p )
{
	struct riocket_rxparam *param = (struct riocket_rxparam *)p;

	dev_dbg(&param->node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,
					param->node->rdev->destid);

	if( param == NULL || param->skb == NULL  ) {
		dev_err(&param->node->rdev->dev,"Tx cb param corrupted\n");
		return;
	}

	if ( stats.transitpktcount > stats.maxintransitpkt ) {
		stats.maxintransitpkt = stats.transitpktcount;
	}

	stats.transitpktcount=0;

	if( (param->node->act_write +1) == param->node->ringsize)
		param->node->act_write = 0;
	else
		param->node->act_write += 1;

	if ( netif_queue_stopped(param->node->ndev ) )
		netif_wake_queue(param->node->ndev);

	dma_unmap_sg(nets[param->node->netid].dmachan->device->dev,
						&param->sgl , 1 ,DMA_TO_DEVICE);


	if( !param->skb->xmit_more ||
		((( param->node->act_write +1 )%param->node->ringsize) ==
					param->node->act_read)) {
		dev_dbg(&param->node->rdev->dev,"%s: Sending DB to node %d\n",__FUNCTION__,
											param->node->rdev->destid);
		rio_send_doorbell(param->node->rdev,(rio_db|DB_PKT_RXED|(param->node->act_write<<CMD_SHIFT)));
	} else {
		stats.numxmitmore++;
	}

	param->node->ndev->stats.tx_packets++;
	param->node->ndev->stats.tx_bytes += param->skb->len;

	dev_kfree_skb_irq(param->skb);

	dev_dbg(&param->node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,param->node->rdev->destid);

	kmem_cache_free(riosocket_cache,param);
}

static int riosocket_dma_packet( struct riosocket_node *node, struct sk_buff *skb )
{
	struct riocket_rxparam *param;
	u64 rioaddr;
	struct rio_dma_data tx_data;
	struct dma_async_tx_descriptor *tx = NULL;
	enum dma_ctrl_flags	flags;
	dma_cookie_t	cookie;
	unsigned char *hdr = (unsigned char*)skb->data;

	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

	if ( (( node->posted_write +1 )%node->ringsize) == node->act_read ) {
		dev_dbg(&node->rdev->dev,"%s: Ring full for node %d\n",__FUNCTION__,node->rdev->destid);
		return NETDEV_TX_BUSY;
	}

	param = kmem_cache_alloc(riosocket_cache,GFP_ATOMIC);

	if (param==NULL) {
		dev_dbg(&node->rdev->dev,"%s: Error allocating callback param struct\n",
										__FUNCTION__);
		return -ENOMEM;
	}

	hdr[1] = (unsigned char)(skb->len & 0xFF);
	hdr[2] = (unsigned char)((skb->len >> 8) & 0xFF);

	param->node = node;
	param->skb = skb;

	rioaddr = node->rioaddress + ( node->posted_write * NODE_SECTOR_SIZE);

	sg_set_buf(&param->sgl,(const void*)skb->data, skb->len);

	param->sgl.page_link |= 0x02;
	param->sgl.page_link &= ~0x01;

	/*Map the DMA addresses*/
	if( dma_map_sg( nets[node->netid].dmachan->device->dev, &param->sgl, 1,
					DMA_MEM_TO_DEV) == -EFAULT ) {
		kmem_cache_free(riosocket_cache,param);
		dev_err(&node->rdev->dev,"Error in mapping sgl\n");
		return -EFAULT;
	}

	tx_data.sg = &param->sgl;
	tx_data.sg_len = 1;
	tx_data.rio_addr_u = 0;
	tx_data.rio_addr = rioaddr;
	tx_data.wr_type = RDW_ALL_NWRITE;

	flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;

	tx = rio_dma_prep_xfer(nets[node->netid].dmachan, node->devid, &tx_data, DMA_MEM_TO_DEV, flags);

	if( IS_ERR_OR_NULL(tx) ) {

		dma_unmap_sg( nets[node->netid].dmachan->device->dev, &param->sgl, 1,
							DMA_MEM_TO_DEV );
		kmem_cache_free(riosocket_cache,param);
		
		if( PTR_ERR(tx) == -EBUSY ) {
			return NETDEV_TX_BUSY;
		} else {
			dev_err(&node->rdev->dev,"Error in dma prep\n");
			return -EIO;
		}
	}

	tx->callback = riosocket_tx_cb;
	tx->callback_param = param;

	cookie = dmaengine_submit(tx);

	if (dma_submit_error(cookie)) {
			kmem_cache_free(riosocket_cache,param);
			dev_err(&node->rdev->dev,"Error in submitting dma packet\n");
			return -EIO;
	}

	dma_async_issue_pending(nets[node->netid].dmachan);

	if( (node->posted_write +1) == node->ringsize)
		node->posted_write = 0;
	else
		node->posted_write += 1;


	dev_dbg(&node->rdev->dev,"%s: Sent packet to %llx of size %d on node %d\n",
			__FUNCTION__,rioaddr,skb->len,node->devid);

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);

	return 0;
}

int riosocket_send_broadcast( unsigned int netid, struct sk_buff *skb )
{
	struct riosocket_node *node, *tmp;
	int ret=0,count=0;
	unsigned long flags=0;

	spin_lock_irqsave(&nets[netid].lock,flags);
	list_for_each_entry_safe(node, tmp,
				 &nets[netid].actnodelist, nodelist) {

		dev_dbg(&node->rdev->dev,"%s: Sending broadcast packet to %d\n",
									__FUNCTION__,node->devid);

		if ( !node->ready ) {
			dev_dbg(&node->rdev->dev,"%s: Node %d not ready yet\n",
								__FUNCTION__,node->devid);
			continue;
		}

		if (count)
			atomic_inc(&skb->users);
		count++;

		ret = riosocket_dma_packet( node, skb );
	}
	spin_unlock_irqrestore(&nets[netid].lock,flags);

	if (!count)
		ret = -ENODEV;

	return ret;
}

int riosocket_send_packet( unsigned int netid, unsigned int destid, struct sk_buff *skb )
{
	struct riosocket_node *node;
	int ret;
	unsigned long flags=0;

	spin_lock_irqsave(&nets[netid].lock,flags);
        node = riosocket_get_node_id(&nets[netid].actnodelist,destid);
        spin_unlock_irqrestore(&nets[netid].lock,flags);

	if( node == NULL )
		return -ENODEV;

	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

	if( !node->ready ) {
		dev_dbg(&node->rdev->dev,"%s: Node %d not ready yet\n",
												__FUNCTION__,node->devid);
		return -1;
	}

	dev_dbg(&node->rdev->dev,"%s: Sending packet to node %d\n",__FUNCTION__,destid);

	ret = riosocket_dma_packet( node , skb );

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);

	return ret;
}

int riosocket_packet_drain( struct riosocket_node *node, int budget )
{
	int packetrxed=0,i=0,length;
	struct sk_buff *skb;
	void __iomem *srcaddr;
	void *dstaddr;
	unsigned char __iomem *hdr;


	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

	if( node->mem_read == node->mem_write )
		return 0;
	else if( node->mem_write > node->mem_read )
		packetrxed = node->mem_write - node->mem_read;
	else
		packetrxed = node->ringsize - node->mem_read;

	dev_dbg(&node->rdev->dev,"%s: Number of packets to be processed=%d\n",
			__FUNCTION__,packetrxed);

	if( packetrxed > budget  ) {
		packetrxed = min( budget, NAPI_WEIGHT );
		stats.napisaturate++;
	}

	for(i=0; i < packetrxed; i++ ) {

		hdr=(unsigned char*)(node->local_ptr + (node->mem_read*NODE_SECTOR_SIZE));

		length=(hdr[2]<<8) | hdr[1];

		if ( length == 0 ) {
				dev_err(&node->rdev->dev,"%s: Packet with len 0 received!!!!!\n",__FUNCTION__);
		} else {
#ifdef DEBUG
			dma_addr_t paddr = node->buffer_address + (node->mem_read * NODE_SECTOR_SIZE);
			dev_dbg(&node->rdev->dev,"%s: Packet with len %d received at %pa\n",
					__FUNCTION__,length, &paddr);
#endif
			if( hdr[0] == 0xFF ) {
					hdr[1] = 0xFF;
					hdr[2] = 0xFF;
			} else {
					hdr[1] = 0x00;
					hdr[2] = 0x00;
			}

			srcaddr = node->local_ptr + (node->mem_read*NODE_SECTOR_SIZE);

			skb = dev_alloc_skb( length + NET_IP_ALIGN );

			if( skb != NULL  )
					skb_reserve(skb, NET_IP_ALIGN);
			else
					continue;

			dstaddr=skb_put(skb,length);

			dev_dbg(&node->rdev->dev,"%s:Copying - src addr=%p dst addr=%p size=%d\n",
						__FUNCTION__,srcaddr,dstaddr,length);

			memcpy(dstaddr,srcaddr,length);

			skb->dev = node->ndev;
			skb->protocol = eth_type_trans(skb, node->ndev);
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb_shinfo(skb)->nr_frags = 0;

			node->ndev->stats.rx_packets++;
			node->ndev->stats.rx_bytes += skb->len;

			netif_receive_skb(skb);
		}

		if( (node->mem_read + 1) == node->ringsize )
			node->mem_read = 0;
		else
			node->mem_read++;
	}

	rio_send_doorbell(node->rdev, rio_db|DB_UPD_RD_CNT|(node->mem_read<<CMD_SHIFT));

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);

	return packetrxed;
}

void riosocket_send_hello_ack_msg( struct rio_dev *rdev )
{
	unsigned short msg=0;
	struct riosocket_node *node;

	dev_dbg(&rdev->dev,"%s: Start (%d)\n",__FUNCTION__,rdev->destid);

	node=riosocket_get_node(&nets[rdev->net->id].actnodelist,rdev);

	msg = DB_HELLO_ACK_1;
	msg |= (u16)((((node->buffer_address - rio_phys_mem) + rio_base_addr) >> 12) << CMD_SHIFT);

	rio_send_doorbell(rdev,rio_db|msg);

	dev_dbg(&rdev->dev,"%s: Sent ack1 with %x\n",__FUNCTION__,msg);

	msg = DB_HELLO_ACK_2;
	msg |= (u16)((((node->buffer_address - rio_phys_mem) + rio_base_addr) >> 24 ) << CMD_SHIFT);

	rio_send_doorbell(rdev,rio_db|msg);

	dev_dbg(&rdev->dev,"%s: Sent ack2 with %x\n",__FUNCTION__,msg);

	dev_dbg(&rdev->dev,"%s: End (%d)\n",__FUNCTION__,rdev->destid);
}

void riosocket_send_hello_msg( unsigned char netid )
{
	struct riosocket_node *node;
	struct list_head *ele;
	unsigned long flags;

	spin_lock_irqsave(&nets[netid].lock,flags);

	list_for_each (ele,&nets[netid].actnodelist) {
			node=(struct riosocket_node*)list_entry(ele, struct riosocket_node, nodelist);
		rio_send_doorbell(node->rdev,rio_db|DB_HELLO);

		dev_dbg(&node->rdev->dev,"%s: Sent hello to %d node\n",__FUNCTION__,node->rdev->destid);
	}

	spin_unlock_irqrestore(&nets[netid].lock,flags);

}

void riosocket_send_bye_msg( unsigned char netid )
{
	struct riosocket_node *node;
	struct list_head *ele;

	spin_lock(&nets[netid].lock);

	list_for_each (ele,&nets[netid].actnodelist) {
			node=(struct riosocket_node*)list_entry(ele, struct riosocket_node, nodelist);
		rio_send_doorbell(node->rdev,rio_db|DB_BYE);

		dev_dbg(&node->rdev->dev,"%s: Sent bye to %d node\n",__FUNCTION__,node->rdev->destid);
	}

	spin_unlock(&nets[netid].lock);

}

static void riosocket_inb_dbell_event( struct rio_mport *mport, void *network, unsigned short sid,
		unsigned short tid, unsigned short info )
{
	struct riosocket_network *net = (struct riosocket_network*)network;
	struct riosocket_node *node;
	unsigned char cmd=(info&DB_CMD_MASK);
	unsigned long long linfo=info;

        node = riosocket_get_node_id(&net->actnodelist,sid);

	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

	if (cmd == DB_HELLO) {

		dev_dbg(&mport->dev,"%s:Received hello command from node %d\n",__FUNCTION__,sid);

		if ( !node->hellorxed ) {
				node->hellorxed=1;
				riosocket_send_hello_ack_msg(node->rdev);
		}

		/*Send a hello command incase during opening of network connection was not alive*/
		if ( !node->rioaddress )
				rio_send_doorbell(node->rdev,DB_HELLO);

		node->mem_read=0;
		node->mem_write=0;
		node->act_read=0;
		node->act_write=0;
		node->posted_write=0;

	} else if (cmd == DB_HELLO_ACK_1) {

		dev_dbg(&mport->dev,"%s:Received hello ack1 command from node %d with %x info\n",
											__FUNCTION__,sid,info);
		node->rioaddress|=((linfo >> CMD_SHIFT) << 12);

	} else if (cmd == DB_HELLO_ACK_2) {

		dev_dbg(&mport->dev,"%s:Received hello ack2 command from node %d with %x info\n",
					__FUNCTION__,sid,info);
		node->rioaddress|=((linfo >> CMD_SHIFT) << 24);
		node->ready=1;
		dev_dbg(&mport->dev,"%s:Node %d remote address %llx\n",__FUNCTION__,
									sid,node->rioaddress);
	} else if (cmd == DB_BYE) {

		dev_dbg(&mport->dev,"%s:Received bye command from node %d\n",__FUNCTION__,sid);
		node->ready=0;
		node->hellorxed=0;
		node->mem_read=0;
		node->mem_write=0;
		node->act_read=0;
		node->act_write=0;
		node->posted_write=0;

	} else if (cmd == DB_PKT_RXED) {

		dev_dbg(&mport->dev,"%s:Received n/w packet command from node %d with write index %d\n",
							__FUNCTION__,sid,(info>>CMD_SHIFT));

		node->mem_write = info>>CMD_SHIFT;

		if (napi_schedule_prep(&node->napi))
				__napi_schedule(&node->napi);

	} else if (cmd == DB_UPD_RD_CNT) {

		dev_dbg(&mport->dev,"%s:Received read count update packet command from node %d with read index %d\n",
					__FUNCTION__,sid,(info>>CMD_SHIFT));
		node->act_read =  info>>CMD_SHIFT;
		netif_wake_queue(node->ndev);

	} else {

		dev_dbg(&mport->dev,"Received unknown command from node %d\n",sid);
	}

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);
}

static int riosocket_rio_probe(struct rio_dev *rdev, const struct rio_device_id *id)
{
	unsigned int srcops,dstops;
	struct riosocket_node *node=NULL;
	int ret=0;
	unsigned char netid=rdev->net->id;
	phys_addr_t net_phys_mem;

	dev_dbg(&rdev->dev,"%s: Probe %d device\n",__FUNCTION__,rdev->destid);

	if (netid >= MAX_NETS) {
		return -EINVAL;
	}

	net_phys_mem = rio_phys_mem + (rio_ibw_size * netid);

	/*check if the network is already initialized. If not, carry out
	 * per adapter network init*/
	if (!(net_table & (0x1 << netid))) {

		struct page *page;

		if ((net_phys_mem + rio_ibw_size) >
				(rio_phys_mem + rio_phys_size)) {
			dev_err(&rdev->net->hport->dev,
				"Invalid memory configuration for net=%d\n",
				netid);
			return -EINVAL;
		}

		dev_dbg(&rdev->dev,"%s:Initializing network %d",__FUNCTION__,netid);

		rio_local_read_config_32(rio_get_mport(rdev), RIO_SRC_OPS_CAR,
				 &srcops);
		rio_local_read_config_32(rio_get_mport(rdev), RIO_DST_OPS_CAR,
				 &dstops);

		if (!is_rionet_capable(srcops, dstops)) {
			dev_err(&rdev->dev,"Mport not capable of messaging\n");
			return -EINVAL;
		}

		nets[netid].id=netid;
		nets[netid].mport   = rio_get_mport(rdev);
		spin_lock_init(&nets[netid].lock);
		INIT_LIST_HEAD(&nets[netid].actnodelist);
		nets[netid].dmachan = rio_request_dma(rdev);

		if (nets[netid].dmachan == NULL) {
				dev_err(&rdev->dev,"Error in allocating DMA channel\n");
			return -ENOMEM;
		}

		/*We direct map the rio address to pcie memory.
		 * FIXME: Get the max memory populated and dynamically configure the number of
		 * inbound mappings needed in multiple of 16GB */
		page = pfn_to_page(PFN_DOWN(net_phys_mem));

		nets[netid].dma_base = dma_map_page(nets[netid].mport->dev.parent, page,
				      0, rio_ibw_size, DMA_BIDIRECTIONAL);
		if (dma_mapping_error(nets[netid].mport->dev.parent, nets[netid].dma_base)) {
			dev_err(nets[netid].mport->dev.parent, "Failed to map DMA page\n");
			ret = -EIO;
			goto freedma;
		}

		ret = rio_map_inb_region(rio_get_mport(rdev), nets[netid].dma_base,
					 rio_base_addr + rio_ibw_size * netid,
					 rio_ibw_size , 0);
		if (ret) {
			dev_err(&rdev->dev, "Error %d in mapping inbound window\n", ret);
			dma_unmap_page(nets[netid].mport->dev.parent, nets[netid].dma_base, rio_ibw_size, DMA_BIDIRECTIONAL);
			goto freedma;
		}

		/*Get the doorbell whcih will be used to exchange IPC and link information*/
		if ((ret=rio_request_inb_dbell(rio_get_mport(rdev),
						(void *)&nets[netid],
						(rio_db|DB_START),
						(rio_db|DB_END),
						riosocket_inb_dbell_event)) < 0) {
				dev_err(&rdev->dev,"Error in allocating inbound doorbell\n");
			goto freeinbmem;
		}

		/*Do vnic initializations*/
		if((ret=riosocket_netinit(&nets[netid])) < 0)
				goto freedb;

        	if ((ret = rio_request_inb_mbox(rio_get_mport(rdev),
                                   (void *)nets[netid].ndev,
                                   RIONET_MAILBOX,
                                   RIONET_RX_RING_SIZE,
                                   riosocket_inb_msg_event)) < 0)
                	goto freeimb;

        	if ((ret = rio_request_outb_mbox(rio_get_mport(rdev),
                                (void *)nets[netid].ndev,
                                RIONET_MAILBOX,
                                RIONET_TX_RING_SIZE,
                                riosocket_outb_msg_event)) < 0)
                	goto freeomb;

		net_table |= (0x1 << netid);
			
	} else if (nets[netid].ndev == NULL) {
			dev_err(&rdev->dev,"No associated vnic found for network = %d\n",netid);
		return -EINVAL;
	}

	/*Initialize the node*/
	if (dev_is_rionet_capable(rdev)) {

		unsigned long flags;

		if (!(node = kzalloc(sizeof(struct riosocket_node),GFP_KERNEL))) {
			ret=-ENOMEM;
			goto freenode;
		}

		node->ndev = nets[netid].ndev;
		node->rdev = rdev;
		node->devid = rdev->destid;
		node->netid = netid;
		INIT_LIST_HEAD(&node->mclist);
		node->ringsize=NODE_MEMLEN/NODE_SECTOR_SIZE;

		if ( rio_phys_mem && rio_phys_size ) {
			node->buffer_address = net_phys_mem +
						(node->devid * NODE_MEMLEN);

			if ((node->buffer_address + NODE_MEMLEN) >
			    (net_phys_mem + rio_ibw_size )) {
				dev_err(&rdev->dev,"Device memory overflow\n");
				goto freenode;
			}

#ifdef CONFIG_PPC
			node->local_ptr = ioremap_prot(node->buffer_address,
						NODE_MEMLEN,
						pgprot_val(pgprot_cached(__pgprot(0))));
#else
			node->local_ptr = ioremap_cache(node->buffer_address,NODE_MEMLEN);
#endif
		} else {
			node->local_ptr = dma_zalloc_coherent(rdev->net->hport->dev.parent,NODE_MEMLEN,
										&node->buffer_address,GFP_KERNEL);
		}

		if( node->local_ptr == NULL ) {
			dev_err(&rdev->dev,"Error in allocating coherent memory\n");
			ret=-ENOMEM;
			goto freenode;
		}

		dev_dbg(&rdev->dev,"%s: Node %d allocated coherent memory at %pa\n",
						__FUNCTION__,rdev->destid, &node->buffer_address);

		if (!(node->db_res = rio_request_outb_dbell(node->rdev,
							(rio_db|DB_START),
							(rio_db|DB_END)))) {
			dev_err(&rdev->dev,"Error requesting RapidIO resources");
			ret=-ENOMEM;
			goto freenode;
		}
		
		riosocket_node_napi_init(node);

		spin_lock_irqsave(&nets[netid].lock, flags);
		list_add_tail(&node->nodelist, &nets[netid].actnodelist);
		spin_unlock_irqrestore(&nets[netid].lock,flags);

		dev_info(&rdev->dev,"Node %d successfully initialized",node->devid);
	}

	rio_set_drvdata(rdev, nets[netid].ndev);

	return 0;

freeomb:
        rio_release_inb_mbox(nets[netid].mport, RIONET_MAILBOX);
freeimb:
        rio_release_outb_mbox(nets[netid].mport, RIONET_MAILBOX);
freedb:
	rio_release_inb_dbell( nets[netid].mport, (rio_db|DB_START),
			(rio_db|DB_END));
freeinbmem:
	dma_unmap_page(nets[netid].mport->dev.parent, nets[netid].dma_base,
		       rio_ibw_size, DMA_BIDIRECTIONAL);
	rio_unmap_inb_region(rio_get_mport(rdev), nets[netid].dma_base);
freedma:
	rio_release_dma(nets[netid].dmachan);
freenode:
	if( node ) {
		if( node->local_ptr ) {
			if ( rio_phys_mem && rio_phys_size )
				iounmap(node->local_ptr);
			else
				dma_free_coherent(rdev->net->hport->dev.parent,NODE_MEMLEN,
						node->local_ptr,node->buffer_address);
		}
		kfree(node);
	}
	return ret;
}	

static void riosocket_rio_remove(struct rio_dev *rdev)
{
	unsigned char netid=rdev->net->id;
	struct riosocket_node *node;

	dev_dbg(&rdev->dev,"%s:Remove device %d\n",__FUNCTION__,rdev->destid);

	node=riosocket_get_node(&nets[netid].actnodelist,rdev);

	if (node) {
		riosocket_node_napi_deinit(node);
		
		spin_lock(&nets[netid].lock);

		if( node->db_res )
			rio_release_outb_dbell(node->rdev, node->db_res);

		if( node->local_ptr ) {
			if ( rio_phys_mem && rio_phys_size )
				iounmap(node->local_ptr);
			else
				dma_free_coherent(rdev->net->hport->dev.parent,NODE_MEMLEN,
							node->local_ptr,node->buffer_address);
		}

		list_del(&node->nodelist);
		kfree(node);

		spin_unlock(&nets[netid].lock);
	}
}

static struct rio_driver riosocket_rio_driver = {
	.name     = "riosocket",
	.id_table = riosocket_id_table,
	.probe    = riosocket_rio_probe,
	.remove   = riosocket_rio_remove,
};

static int __init riosocket_net_init(void)
{
	pr_info("RIOSocket Driver Version %s Initialization...\n",RIOSOCKET_VERSION);

	if(rio_phys_mem && rio_phys_size) {
			pr_info("Using %lx - %lx for local memory allocation (0x%lx per net)\n",
				rio_phys_mem,
				(rio_phys_mem + rio_phys_size - 1), rio_ibw_size);
	} else {
		/*TODO:Need to add support for using dma routines to allocate remote memory*/
		pr_info("%s: Please specify rio_phys_mem:rio_phys_size\n",
			__func__);
		return -EINVAL;
	}

	if (!(riosocket_cache =kmem_cache_create("riosocket_cache",
			  sizeof(struct riocket_rxparam), 0, 0 ,NULL))) {
		 return -ENOMEM;
	}

	memset( nets, 0 , (sizeof(struct riosocket_network)*MAX_NETS));
	memset( &stats, 0, sizeof(struct riosocket_driver_params));

	riosocket_rio_driver.driver.groups=riosocket_drv_attr_groups;

	rio_register_driver(&riosocket_rio_driver);

	pr_info("%s: Done\n", __func__);

	return 0;
}

static void __exit riosocket_net_exit(void)
{
	unsigned char i;

	pr_info("RIOSocket Driver Initialization Unloading\n");

	rio_unregister_driver(&riosocket_rio_driver);

	for( i=0; i < MAX_NETS; i++ ) {

		if (nets[i].mport) {

			if (nets[i].ndev)
				riosocket_netdeinit(&nets[i]);

			spin_lock(&nets[i].lock);

			rio_release_inb_dbell(nets[i].mport, (rio_db|DB_START),
					      (rio_db | DB_END));

			dma_unmap_page(nets[i].mport->dev.parent,
				       nets[i].dma_base, rio_ibw_size,
				       DMA_BIDIRECTIONAL);
			rio_unmap_inb_region(nets[i].mport,
					     nets[i].dma_base);

			rio_release_dma(nets[i].dmachan);
			rio_release_inb_mbox(nets[i].mport, RIONET_MAILBOX);
			rio_release_outb_mbox(nets[i].mport, RIONET_MAILBOX);

			spin_unlock(&nets[i].lock);
		}
	}

	kmem_cache_destroy(riosocket_cache);

	pr_info("%s: Done\n", __func__);
}


module_init(riosocket_net_init);
module_exit(riosocket_net_exit);
