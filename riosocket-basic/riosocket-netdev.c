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

static int riosocket_start_xmit_dma( struct sk_buff *skb, struct net_device *netdev )
{
	struct riosocket_private *priv;
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	unsigned int destid=riosocket_get_node_id_from_mac(eth->h_dest);
	struct riosocket_msg_private *rnet;
	int ret=0;

	priv = (struct riosocket_private*)netdev_priv(netdev);
	rnet = (struct riosocket_msg_private *)&priv->rnetpriv;

	dev_dbg(&netdev->dev,"%s: Sending packet to node %d\n",__FUNCTION__,
													destid);
	if( destid == BROADCAST || is_multicast_ether_addr(eth->h_dest))
		ret = riosocket_send_broadcast( priv->netid, skb );
	else
		ret = riosocket_send_packet( priv->netid,destid, skb );

	/* Don't wait up for transmitted skbs to be freed. */
	skb_orphan(skb);
	nf_reset(skb);

	if( ret == NETDEV_TX_BUSY ) {
		dev_dbg(&netdev->dev,"%s: Ring full. Stopping network queue\n",__FUNCTION__);
		stats.txringfull++;
		netif_stop_queue(netdev);
	} else if ( ret != 0 ) {
		dev_dbg(&netdev->dev,"%s: Something went wrong during transmission\n",__FUNCTION__);
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
	int ret=0;

	dev_dbg(&netdev->dev,"%s: Start\n",__FUNCTION__);

	if( skb->len > NODE_SECTOR_SIZE ) {
		dev_dbg(&netdev->dev,"%s: skb size greater than mtu!\n",__FUNCTION__);
		return -EINVAL;
	}

	if( skb == NULL ) {
		return -EINVAL;
	}

	if( skb->len > msgwatermark )
		ret=riosocket_start_xmit_dma(skb,netdev);
	else
		ret=riosocket_start_xmit_msg(skb,netdev);

	dev_dbg(&netdev->dev,"%s: End\n",__FUNCTION__);

	return ret;

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

		riosocket_send_hello_msg(priv->netid);

		priv->link=1;
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

static int riosocket_poll( struct napi_struct *napi, int budget )
{
	struct riosocket_node *node = container_of(napi,struct riosocket_node,napi);
	int ret;

	dev_dbg(&node->rdev->dev,"%s: Start (%d)\n",__FUNCTION__,node->rdev->destid);

	ret = riosocket_packet_drain( node , budget );

	if( ret < budget )
		napi_complete(napi);

	dev_dbg(&node->rdev->dev,"%s: End (%d)\n",__FUNCTION__,node->rdev->destid);

	return ret;
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

	net->ndev->dev_addr[0] = 0xC2;
	net->ndev->dev_addr[1] = 0x00;
	net->ndev->dev_addr[2] = 0x00;
	net->ndev->dev_addr[3] = 0x00;
	net->ndev->dev_addr[4] = rio_local_get_device_id(priv->mport) >> 8;
	net->ndev->dev_addr[5] = rio_local_get_device_id(priv->mport) & 0xff;
	net->ndev->netdev_ops = &riosocket_net_ops;
	net->ndev->mtu = MAX_MTU;
	net->ndev->features =  (NETIF_F_HW_CSUM | NETIF_F_HIGHDMA | NETIF_F_LLTX);

	dev_dbg(&net->ndev->dev,"%s: End\n",__FUNCTION__);

	return register_netdev(net->ndev);
}

int riosocket_netdeinit( struct riosocket_network *net )
{
	dev_dbg(&net->ndev->dev,"%s: Start\n",__FUNCTION__);

	unregister_netdev(net->ndev);
	free_netdev(net->ndev);

	dev_dbg(&net->ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

int riosocket_node_napi_init( struct riosocket_node *node )
{
	netif_napi_add( node->ndev, &node->napi,riosocket_poll, NAPI_WEIGHT );
	napi_enable(&node->napi);

	return 0;
}

int riosocket_node_napi_deinit( struct riosocket_node *node )
{
	napi_disable(&node->napi);
	netif_napi_del( &node->napi );

	return 0;
}
