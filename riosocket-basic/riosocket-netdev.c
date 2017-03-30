/*********************************************************************
 *  Copyright of Centaurus Computing - 2016
 *  Copyright 2017, Integrated Device Technology, Inc.
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
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>

#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

extern unsigned long msgwatermark;

static void riosocket_net_set_multicast (struct net_device *netdev)
{
	dev_dbg(&netdev->dev,"%s: Start\n",__FUNCTION__);
	dev_dbg(&netdev->dev,"%s: End\n",__FUNCTION__);
}

static int riosocket_start_xmit_dma(struct sk_buff *skb,
				    struct net_device *netdev, u16 destid)
{
	struct riosocket_private *priv;
	struct riosocket_msg_private *rnet;
	int ret=0;

	priv = netdev_priv(netdev);
	rnet = &priv->rnetpriv;

	dev_dbg(&netdev->dev, "%s: Sending packet to node %d\n",
		__func__, destid);

	if (destid == BROADCAST)
		ret = riosocket_send_broadcast( priv->netid, skb );
	else
		ret = riosocket_send_packet( priv->netid,destid, skb );

	if (ret == NETDEV_TX_BUSY) {
		dev_dbg(&netdev->dev, "%s: DMA ring is full.\n", __func__);
		stats.txringfull++;
	} else if (ret) {
		dev_dbg(&netdev->dev, "%s: DMA TX err=%d\n", __func__, ret);
		netdev->stats.tx_dropped++;
		dev_kfree_skb_any(skb);
	} else {
		ret = NETDEV_TX_OK;
		stats.transitpktcount++;
	}

	return ret;
}

static int riosocket_net_start_xmit(struct sk_buff *skb, struct net_device *netdev)
{
	struct riosocket_private *priv;
	struct ethhdr *eth;

	dev_dbg(&netdev->dev,"%s: Start\n",__FUNCTION__);

	if (!skb)
		return -EIO;

	if (skb->len > NODE_SECTOR_SIZE) {
		dev_info(&netdev->dev,
			"%s: skb size greater than max sector size!\n",
			__func__);
		dev_kfree_skb_any(skb);
		netdev->stats.tx_dropped++;
		return -EINVAL;
	}

	eth = (struct ethhdr *)skb->data;
	priv = netdev_priv(netdev);

	if (skb_queue_len(&priv->tx_queue) > RSOCK_TX_QUEUE_OFF)
		netif_stop_queue(netdev);

	eth->h_source[1] = (unsigned char)(skb->len & 0xFF);
	eth->h_source[2] = (unsigned char)((skb->len >> 8) & 0xFF);

	skb_queue_tail(&priv->tx_queue, skb);
	tasklet_schedule(&priv->tx_tasklet);
	return NETDEV_TX_OK;
}

static int riosocket_net_open(struct net_device *netdev)
{
	struct riosocket_private *priv;
	int ret=0;

	dev_dbg(&netdev->dev,"%s: Start\n",__FUNCTION__);

	priv = (struct riosocket_private*)netdev_priv(netdev);

	if (!(ret=riosocket_open(netdev))) {
		netif_carrier_on(netdev);
		netif_start_queue(netdev);
		priv->link=1;
		riosocket_send_hello_msg(priv->netid);
	} else {
		dev_err(&netdev->dev,"Error init msg engine\n");
	}

	dev_dbg(&netdev->dev,"%s: End\n",__FUNCTION__);

	return ret;
}

static int riosocket_net_close(struct net_device *netdev)
{
	struct riosocket_private *priv;

	dev_dbg(&netdev->dev,"%s: Start\n",__FUNCTION__);

	netif_stop_queue(netdev);
	netif_carrier_off(netdev);

	priv = (struct riosocket_private*)netdev_priv(netdev);
	priv->link=0;

	riosocket_send_bye_msg(priv->netid);

	riosocket_close(netdev);

	dev_dbg(&netdev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

static int rsock_check_rx_queue(struct riosocket_node *node,
				 int budget, int *rxd)
{
	struct sk_buff *skb;
	int i;

	for (i = 0; i < budget; i++) {
		skb = skb_dequeue(&node->rx_queue);
		if (!skb)
			break;

		skb->dev = node->ndev;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		skb->protocol = eth_type_trans(skb, node->ndev);
		skb_shinfo(skb)->nr_frags = 0;

		++node->ndev->stats.rx_packets;
		node->ndev->stats.rx_bytes += skb->len;

		netif_receive_skb(skb);
	}

	if (rxd)
		*rxd = i;

	return (i) ? 0 : -ENOMSG;
}

static int riosocket_rx_poll(struct napi_struct *napi, int budget)
{
	struct riosocket_node *node = container_of(napi,struct riosocket_node,napi);
	int ret;
	int rx_total = 0, rxd;

	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

poll_repeat:
	ret = rsock_check_rx_queue(node, budget - rx_total, &rxd);
	if (!ret)
		rx_total += rxd;

	if (rx_total < budget) {
		napi_complete(napi);

		if (!skb_queue_empty(&node->rx_queue) && napi_reschedule(napi))
			goto poll_repeat;
	}

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);

	return rx_total;
}

static void rsock_tx_tasklet(unsigned long data)
{
	struct riosocket_private *priv;
	struct sk_buff *skb;
	struct ethhdr *eth;
	struct net_device *netdev;
	u16 destid;
	int i, ret;

	priv = (struct riosocket_private *)data;
	netdev = nets[priv->netid].ndev;

	for (i = 0; i < RSOCK_TX_BUDGET; i++) {
		skb = skb_dequeue(&priv->tx_queue);
		if (!skb)
			break;

		eth = (struct ethhdr *)skb->data;

		if (is_multicast_ether_addr(eth->h_dest))
			destid = BROADCAST;
		else
			destid = riosocket_get_destid_from_mac(eth->h_dest);

		if (skb->len > msgwatermark &&
					atomic_read(&priv->msg_pending) == 0) {
			ret = riosocket_start_xmit_dma(skb, netdev, destid);
			if (ret && ret != NETDEV_TX_BUSY)
				dev_info(&netdev->dev,
					"%s: start_xmit_dma failed (err=%d)\n",
					__func__, ret);
		} else if (skb->len <= msgwatermark &&
					atomic_read(&priv->dma_pending) == 0) {
			ret = riosocket_start_xmit_msg(skb, netdev, destid);
			if (ret && ret != NETDEV_TX_BUSY)
				dev_info(&netdev->dev,
					"%s: start_xmit_msg failed (err=%d)\n",
					__func__, ret);
		} else
			ret = NETDEV_TX_BUSY;

		if (ret == NETDEV_TX_BUSY) {
			/* MSG TX channel is busy.
			 * Return skb into the queue and reschedule the tasklet
			 */
			skb_queue_head(&priv->tx_queue, skb);
			break;
		}
	}

	if (skb_queue_len(&priv->tx_queue) < RSOCK_TX_QUEUE_ON)
		netif_wake_queue(netdev);

	if (!skb_queue_empty(&priv->tx_queue))
		tasklet_schedule(&priv->tx_tasklet);
}

void riosocket_eth_setup(struct net_device *ndev)
{
	ether_setup(ndev);
}

static int riosocket_net_change_mtu(struct net_device *ndev, int newmtu)
{
	if( newmtu > MAX_MTU )
		ndev->mtu = MAX_MTU;
	else if( newmtu < 32 )
		return -EINVAL;
	else
		ndev->mtu = newmtu;

	return 0;
}

static const struct net_device_ops riosocket_net_ops = {
.ndo_open                               = riosocket_net_open,
.ndo_stop                               = riosocket_net_close,
.ndo_start_xmit                         = riosocket_net_start_xmit,
.ndo_change_mtu                         = riosocket_net_change_mtu,
.ndo_validate_addr                      = eth_validate_addr,
.ndo_set_rx_mode                        = riosocket_net_set_multicast,
};

int riosocket_netinit( struct riosocket_network *net )
{
	struct riosocket_private *priv;
	char netname[20];

	sprintf(netname, "%s%d", "rsock",net->id);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 17, 0)
	net->ndev = alloc_netdev( sizeof(struct riosocket_private) , netname ,NET_NAME_UNKNOWN,
								riosocket_eth_setup );
	#else
	net->ndev = alloc_netdev( sizeof(struct riosocket_private) , netname ,
								riosocket_eth_setup );
	#endif

	if (net->ndev == NULL) {
			dev_err(&net->ndev->dev,"Error in allocating network device struct");
			return -ENOMEM;
	}

	dev_dbg(&net->ndev->dev,"%s: Start\n",__FUNCTION__);

	priv = (struct riosocket_private*)netdev_priv(net->ndev);

	memset(priv, 0 , sizeof(struct riosocket_private));

	priv->mport = net->mport;
	priv->netid = net->id;
	priv->link  = 0;
	priv->rnetpriv.mport = net->mport;
	spin_lock_init(&priv->rnetpriv.lock);
	spin_lock_init(&priv->rnetpriv.tx_lock);
	skb_queue_head_init(&priv->tx_queue);
	atomic_set(&priv->dma_pending, 0);
	atomic_set(&priv->msg_pending, 0);
	tasklet_init(&priv->tx_tasklet, rsock_tx_tasklet, (unsigned long)priv);

	net->ndev->dev_addr[0] = 0xC2;
	net->ndev->dev_addr[1] = 0x00;
	net->ndev->dev_addr[2] = 0x00;
	net->ndev->dev_addr[3] = 0x00;
	net->ndev->dev_addr[4] = rio_local_get_device_id(priv->mport) >> 8;
	net->ndev->dev_addr[5] = rio_local_get_device_id(priv->mport) & 0xff;
	net->ndev->netdev_ops = &riosocket_net_ops;
	net->ndev->mtu = MAX_MTU;
	net->ndev->features =  (NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX);
	SET_NETDEV_DEV(net->ndev, &net->mport->dev);

	dev_dbg(&net->ndev->dev,"%s: End\n",__FUNCTION__);

	return register_netdev(net->ndev);
}

int riosocket_netdeinit( struct riosocket_network *net )
{
	struct riosocket_private *priv;

	dev_dbg(&net->ndev->dev,"%s: Start\n",__FUNCTION__);

	priv = (struct riosocket_private *)netdev_priv(net->ndev);

	tasklet_kill(&priv->tx_tasklet);
	unregister_netdev(net->ndev);
	free_netdev(net->ndev);
	net->ndev = NULL;

	dev_dbg(&net->ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

int riosocket_node_napi_init( struct riosocket_node *node )
{
	netif_napi_add(node->ndev, &node->napi, riosocket_rx_poll, NAPI_WEIGHT);
	napi_enable(&node->napi);

	return 0;
}

int riosocket_node_napi_deinit( struct riosocket_node *node )
{
	napi_disable(&node->napi);
	netif_napi_del( &node->napi );

	return 0;
}
