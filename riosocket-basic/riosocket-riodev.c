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
#include <linux/reboot.h>

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
MODULE_PARM_DESC(rio_base_addr, "Inbound RapidIO window base address");

unsigned long rio_ibw_size = DEFAULT_IBW_SIZE;
module_param(rio_ibw_size, ulong , S_IRUGO);
MODULE_PARM_DESC(rio_ibw_size, "Inbound mapping window size for each mport");

extern const struct attribute_group *riosocket_drv_attr_groups[];
struct riosocket_driver_params stats;
struct riosocket_network nets[MAX_NETS];

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

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0))
	dev_kfree_skb_irq(param->skb);
#else
	dev_consume_skb_irq(param->skb);
#endif

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
	tx_data.wr_type = RDW_LAST_NWRITE_R;
	tx_data.ssdist = 0;
	tx_data.sssize = 0;
	tx_data.dsdist = 0;
	tx_data.dssize = 0;

	flags = DMA_CTRL_ACK | DMA_PREP_INTERRUPT;

	tx = rio_dma_prep_xfer(nets[node->netid].dmachan, node->devid, &tx_data, DMA_MEM_TO_DEV, flags);

	if( IS_ERR_OR_NULL(tx) ) {

		dma_unmap_sg( nets[node->netid].dmachan->device->dev, &param->sgl, 1,
							DMA_MEM_TO_DEV );
		kmem_cache_free(riosocket_cache,param);
		
		if( PTR_ERR(tx) == -EBUSY ) {
			return NETDEV_TX_BUSY;
		} else {
			dev_err(&node->rdev->dev,"Error %ld in DMA xfer prep\n",
				PTR_ERR(tx));
			return PTR_ERR(tx);
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
	struct riosocket_node *node;
	int ret=0,count=0;
	unsigned long flags=0;

	spin_lock_irqsave(&nets[netid].lock,flags);
	list_for_each_entry(node,
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

void riosocket_send_hello_msg(unsigned char netid)
{
	struct riosocket_node *node;
	unsigned long flags;

	spin_lock_irqsave(&nets[netid].lock, flags);
	list_for_each_entry(node, &nets[netid].actnodelist, nodelist) {
		rio_send_doorbell(node->rdev, rio_db|DB_HELLO);
		dev_info(&node->rdev->dev, "%s: Sent hello to %d node\n",
			__FUNCTION__, node->rdev->destid);
	}
	spin_unlock_irqrestore(&nets[netid].lock, flags);
}

void riosocket_send_bye_msg(unsigned char netid)
{
	struct riosocket_node *node;
	unsigned long flags;

	spin_lock_irqsave(&nets[netid].lock, flags);
	list_for_each_entry(node, &nets[netid].actnodelist, nodelist) {
		rio_send_doorbell(node->rdev, rio_db|DB_BYE);
		pr_info("riosocket: %s: Sent DB_BYE to node %s\n",
			 __func__, rio_name(node->rdev));
	}
	spin_unlock_irqrestore(&nets[netid].lock, flags);
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
		if (!node->ready)
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

		napi_schedule(&node->napi);

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
	return -ENODEV;
}

/*
 * rsock_prep_mport - request local mport device resources and initialize
 *                    network device
 * @mport: pointer to mport device
 * @net: pointer to network data structure
 * @net_phys_mem: physical address of associated memory block
 *
 * When a new mport device is added reserves required resources
 * and initializes/registers associated network device object.
 */
static int rsock_prep_mport(struct rio_mport *mport,
			struct riosocket_network *net, phys_addr_t net_phys_mem)
{
	struct page *page;
	unsigned int srcops, dstops;
	int ret;

	pr_info("riosocket: prep mport %s net_%d\n", mport->name, net->id);

	if ((net_phys_mem + rio_ibw_size) > (rio_phys_mem + rio_phys_size)) {
		dev_err(&mport->dev,
			"Invalid memory configuration for net_%d\n", net->id);
			return -EINVAL;
	}

	pr_info("riosocket: Initializing network %d", net->id);

	rio_local_read_config_32(mport, RIO_SRC_OPS_CAR, &srcops);
	rio_local_read_config_32(mport, RIO_DST_OPS_CAR, &dstops);

	if (!is_rionet_capable(srcops, dstops)) {
		pr_err("riosocket: MPORT (%s) not capable of messaging\n",
			mport->name);
		return -EINVAL;
	}

	net->mport = mport;
	spin_lock_init(&net->lock);
	INIT_LIST_HEAD(&net->actnodelist);
	net->dmachan = rio_request_mport_dma(mport);

	if (!net->dmachan) {
		dev_err(&mport->dev,"Error in allocating DMA channel\n");
		return -ENODEV;
	}

	page = pfn_to_page(PFN_DOWN(net_phys_mem));

	net->dma_base = dma_map_page(mport->dev.parent, page, 0, rio_ibw_size,
				     DMA_BIDIRECTIONAL);
	if (dma_mapping_error(mport->dev.parent, net->dma_base)) {
		dev_err(mport->dev.parent, "Failed to map DMA page\n");
		ret = -EIO;
		goto err_map_dma;
	}

	ret = rio_map_inb_region(mport, net->dma_base,
				 rio_base_addr + (rio_ibw_size * net->id),
				 rio_ibw_size , 0);
	if (ret) {
		dev_err(&mport->dev,
			"Error %d in mapping inbound window\n", ret);
		dma_unmap_page(mport->dev.parent, net->dma_base, rio_ibw_size,
			       DMA_BIDIRECTIONAL);
		goto err_map_ibw;
	}

	/*
	 * Get IDB range which will be used to exchange IPC and link information
	 */
	ret = rio_request_inb_dbell(mport, net,
				    rio_db | DB_START, rio_db | DB_END,
				    riosocket_inb_dbell_event);
	if (ret) {
		dev_err(&mport->dev, "Error in allocating inbound doorbell\n");
		goto err_idb;
	}

	ret = riosocket_netinit(net);
	if (ret) {
		dev_err(&mport->dev,"NDEV initialization failed err=%d\n", ret);
		goto err_netinit;
	}

	ret = rio_request_inb_mbox(mport, net->ndev,
				RIONET_MAILBOX, RIONET_RX_RING_SIZE,
				riosocket_inb_msg_event);
	if (ret) {
		dev_err(&mport->dev,
			"Failed to obtain IB_MBOX err=%d\n", ret);
		goto err_imb;
	}

	ret = rio_request_outb_mbox(mport, net->ndev,
				RIONET_MAILBOX, RIONET_TX_RING_SIZE,
				riosocket_outb_msg_event);
	if (ret) {
		dev_err(&mport->dev,
			"Failed to obtain OB_MBOX err=%d\n", ret);
		goto err_omb;
	}

	return 0;

err_omb:
        rio_release_inb_mbox(mport, RIONET_MAILBOX);
err_imb:
	riosocket_netdeinit(net);
err_netinit:
	rio_release_inb_dbell(mport, rio_db | DB_START, rio_db | DB_END);
err_idb:
	rio_unmap_inb_region(mport, net->dma_base);
err_map_ibw:
	dma_unmap_page(mport->dev.parent, net->dma_base,
		       rio_ibw_size, DMA_BIDIRECTIONAL);
err_map_dma:
	rio_release_dma(net->dmachan);
	net->mport = NULL;
	return ret;
}

/*
 * rsock_add_dev - add new remote RapidIO device
 * @dev: device object associated with RapidIO device
 * @sif: subsystem interface
 *
 * Adds the specified RapidIO device (if applicable) into peers list of
 * the corresponding network.
 */
static int rsock_add_dev(struct device *dev, struct subsys_interface *sif)
{
	struct rio_dev *rdev = to_rio_dev(dev);
	struct riosocket_node *node;
	unsigned char netid;
	phys_addr_t net_phys_mem;
	unsigned long flags;
	struct riosocket_network *net;
	struct riosocket_private *priv;
	int ret;

	netid = rdev->net->id;

	if (netid >= MAX_NETS)
		return -EINVAL;

	net = &nets[netid];
	net_phys_mem = rio_phys_mem + (rio_ibw_size * netid);

	if (!net->mport) {
		dev_info(&rdev->dev, "%s: Initialize MPORT\n", __func__);
		net->id = netid;
		ret = rsock_prep_mport(rdev->net->hport, net, net_phys_mem);
		if (ret) {
			dev_err(&rdev->dev,
				"%s: MPORT initialization failed (err=%d)\n",
				__func__, ret);
			return ret;
		}
	}

	if (!dev_is_rionet_capable(rdev))
		return 0;

	pr_info("riosocket: add device %s\n", rio_name(rdev));

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node) {
		return -ENOMEM;
	}

	node->ndev = net->ndev;
	node->netid = netid;
	node->rdev = rdev;
	node->devid = rdev->destid;
	node->ringsize = NODE_MEMLEN/NODE_SECTOR_SIZE;

	if (rio_phys_mem && rio_phys_size) {
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
		node->local_ptr = ioremap_cache(node->buffer_address,
						NODE_MEMLEN);
#endif
	} else {
		node->local_ptr = dma_zalloc_coherent(
					net->mport->dev.parent,
					NODE_MEMLEN, &node->buffer_address,
					GFP_KERNEL);
	}

	if (node->local_ptr == NULL) {
		dev_err(&rdev->dev, "Failed to allocate coherent memory\n");
		ret =- ENOMEM;
		goto freenode;
	}

	dev_dbg(&rdev->dev,
		"%s: Node %s (%d) allocated coherent memory at %pa\n",
		__func__, rio_name(rdev), rdev->destid, &node->buffer_address);

	node->db_res = rio_request_outb_dbell(node->rdev, rio_db | DB_START,
					      rio_db | DB_END);
	if (!node->db_res) {
		dev_err(&rdev->dev,
			"Error requesting RapidIO outbound doorbells");
		ret = -ENOMEM;
		goto freenode;
	}

	riosocket_node_napi_init(node);

	spin_lock_irqsave(&net->lock, flags);
	list_add_tail(&node->nodelist, &net->actnodelist);
	spin_unlock_irqrestore(&net->lock,flags);

	priv = netdev_priv(net->ndev);
	if (priv->link) {
		rio_send_doorbell(rdev, rio_db | DB_HELLO);
		dev_info(&rdev->dev, "%s: Sent hello to %s (%d)\n",
			__func__, rio_name(rdev), rdev->destid);
	}

	dev_info(&rdev->dev, "%s: Node %s (%d) successfully initialized",
		 __func__, rio_name(rdev), node->devid);

	return 0;

freenode:
	if (node) {
		if (node->local_ptr) {
			if (rio_phys_mem && rio_phys_size)
				iounmap(node->local_ptr);
			else
				dma_free_coherent(net->mport->dev.parent,NODE_MEMLEN,
						node->local_ptr,node->buffer_address);
		}

		kfree(node);
	}

	return ret;
}

/*
 * rsock_remove_dev - remove remote RapidIO device from peer devices list
 * @dev: device object associated with RapidIO device
 * @sif: subsystem interface
 *
 * Removes the specified RapidIO device (if applicable) from peers list of
 * the corresponding network.
 */
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0))
static void
#else
static int
#endif
rsock_remove_dev(struct device *dev, struct subsys_interface *sif)
{
	struct rio_dev *rdev = to_rio_dev(dev);
	unsigned char netid = rdev->net->id;
	struct riosocket_node *node;
	struct riosocket_network *net;
	unsigned long flags;
	int state;
	int ret = 0;

	if (netid >= MAX_NETS) {
		ret = -EINVAL;
		goto exit;
	}

	if (!dev_is_rionet_capable(rdev))
		goto exit;

	net = &nets[netid];

	if (!net->mport) {
		pr_err("riosocket: %s: net_%d MPORT is not initialized\n",
			__func__, netid);
		ret = -EIO;
		goto exit;
	}

	state = atomic_read(&rdev->state);

	pr_info("riosocket: remove device %s (did=%d), state=%d\n",
		rio_name(rdev), rdev->destid, state);

	spin_lock_irqsave(&net->lock, flags);
	node = riosocket_get_node(&net->actnodelist, rdev);
	if (node)
		list_del(&node->nodelist);
	spin_unlock_irqrestore(&net->lock, flags);

	if (node) {
		riosocket_node_napi_deinit(node);

		/*
		 * Removal of active remote device can be caused by local node
		 * shutdown, driver unloading or forced mport device removal.
		 * If this is the case, notify the remote device that we are
		 * leaving (closing connection).
		 */
		if (state == RIO_DEVICE_RUNNING ||
				state == RIO_DEVICE_SHUTDOWN) {
			pr_info("riosocket: %s: Send DB_BYE to node %s\n",
				__func__, rio_name(rdev));
			rio_send_doorbell(rdev, rio_db | DB_BYE);
		}

		if (node->db_res)
			rio_release_outb_dbell(rdev, node->db_res);

		if (node->local_ptr) {
			if (rio_phys_mem && rio_phys_size)
				iounmap(node->local_ptr);
			else
				dma_free_coherent(net->mport->dev.parent,
						  NODE_MEMLEN, node->local_ptr,
						  node->buffer_address);
		}

		kfree(node);
	}

exit: ;
#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,3,0))
	return ret;
#endif
}

/*
 * rsock_remove_mport - service removal of local mport device
 * @dev: device object associated with mport
 * @class_intf: class interface
 *
 * Unregister associated network device and release allocated resources.
 */
static void rsock_remove_mport(struct device *dev,
			       struct class_interface *class_intf)
{
	struct rio_mport *mport = to_rio_mport(dev);
	unsigned char netid = mport->net->id;
	struct riosocket_network *net;

	pr_info("riosocket: remove mport %s\n", mport->name);

	if (netid >= MAX_NETS)
		return;

	net = &nets[netid];

	if (!net->mport)
		return;

	if (net->ndev)
		riosocket_netdeinit(net);
	net->ndev = NULL;

	rio_release_inb_dbell(mport, rio_db | DB_START, rio_db | DB_END);

	dma_unmap_page(mport->dev.parent, net->dma_base, rio_ibw_size,
			DMA_BIDIRECTIONAL);
	rio_unmap_inb_region(mport, net->dma_base);
	rio_release_dma(net->dmachan);
	rio_release_inb_mbox(mport, RIONET_MAILBOX);
	rio_release_outb_mbox(mport, RIONET_MAILBOX);

	net->mport = NULL;
}

static int riosocket_shutdown(struct notifier_block *nb, unsigned long code,
			      void *unused)
{
	int i;

	pr_info("riosocket: %s\n", __func__);

	for (i = 0; i < MAX_NETS; i++) {
		if (nets[i].mport)
			riosocket_send_bye_msg(i);
	}

	return NOTIFY_DONE;
}

/*
 * rsock_interface handles addition/removal of remote RapidIO devices
 */
static struct subsys_interface rsock_interface = {
	.name		= "rsock_if",
	.subsys		= &rio_bus_type,
	.add_dev	= rsock_add_dev,
	.remove_dev	= rsock_remove_dev,
};

/*
 * rio_mport_interface handles addition/removal local mport devices
 */
static struct class_interface rio_mport_interface __refdata = {
	.class = &rio_mport_class,
	.add_dev = NULL,
	.remove_dev = rsock_remove_mport,
};

static struct notifier_block rionet_notifier = {
	.notifier_call = riosocket_shutdown,
};

static struct rio_driver riosocket_rio_driver = {
	.name     = "riosocket",
	.id_table = riosocket_id_table,
	.probe    = riosocket_rio_probe,
};

static int __init riosocket_net_init(void)
{
	int ret;

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


	ret = register_reboot_notifier(&rionet_notifier);
	if (ret) {
		pr_err("%s: failed to register reboot notifier (err=%d)\n",
		       __func__, ret);
		return ret;
	}


	/*
	 * Register as rapidio_port class interface to get notifications about
	 * mport additions and removals.
	 */
	ret = class_interface_register(&rio_mport_interface);
	if (ret) {
		pr_err("class_interface_register error: %d\n", ret);
		return ret;
	}

	/*
	 * Register as RapidIO bus interface to get notifications about
	 * addition/removal of remote RapidIO devices.
	 */
	ret = subsys_interface_register(&rsock_interface);
	if (ret) {
		pr_err("subsys_interface_register error: %d\n", ret);
		class_interface_unregister(&rio_mport_interface);
		return ret;
	}

	/*
	 * FIXME: Temporary keep registering this module as device driver with
	 * dummy probe routine (always returns -ENODEV) to preserve device
	 * driver attributes at the same location as the original version
	 * created by Centaurus Computing.
	 */
	riosocket_rio_driver.driver.groups=riosocket_drv_attr_groups;
	rio_register_driver(&riosocket_rio_driver);

	pr_info("%s: Done\n", __func__);

	return 0;
}

static void __exit riosocket_net_exit(void)
{
	unsigned char i;

	pr_info("%s: RIOSocket Driver Unloading\n", __func__);

	rio_unregister_driver(&riosocket_rio_driver);

	kmem_cache_destroy(riosocket_cache);
	unregister_reboot_notifier(&rionet_notifier);
	subsys_interface_unregister(&rsock_interface);
	class_interface_unregister(&rio_mport_interface);

	for( i=0; i < MAX_NETS; i++ ) {

		if (nets[i].mport) {

			pr_info("%s: ATTN: Cleanup for mport_%d (%s)\n",
				__func__, i, nets[i].mport->name);

			if (nets[i].ndev)
				riosocket_netdeinit(&nets[i]);

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

			nets[i].mport = NULL;
		}
	}

	pr_info("%s: Done\n", __func__);
}

module_init(riosocket_net_init);
module_exit(riosocket_net_exit);
