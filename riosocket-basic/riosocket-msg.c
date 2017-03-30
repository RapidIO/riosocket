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
#include <linux/dma-mapping.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>
#include <linux/ethtool.h>
#include <linux/reboot.h>
#include <linux/version.h>

#include <linux/rio.h>
#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

/*Code reuse from RIONET for cleaner implementation of messaging based
 * smaller packet transfers*/

static int riosocket_rx_clean(struct riosocket_network *net)
{
	int i;
	struct net_device *ndev = net->ndev;
	struct riosocket_private *priv;
	struct riosocket_msg_private *rnet;
	void *data;
	int msg_size;
	struct ethhdr *eth;
	struct riosocket_node *node;
	u16 destid;
	unsigned long flags;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	rnet = &((struct riosocket_private *)netdev_priv(ndev))->rnetpriv;
	priv = netdev_priv(ndev);

	i = rnet->rx_slot;

	do {
		if (!rnet->rx_skb[i])
			continue;

		if (!(data = rio_get_inb_message(rnet->mport, RIONET_MAILBOX,
						 &msg_size)))
			break;

		eth = (struct ethhdr *)data;

		msg_size = (eth->h_source[2] << 8) | eth->h_source[1];

		eth->h_source[1] = 0x00;
		eth->h_source[2] = 0x00;

		destid = GET_DESTID(eth->h_source);
		if (destid == BROADCAST)
			dev_info(&ndev->dev, "%s: ERR: Invalid destid\n",
				__func__);

		spin_lock_irqsave(&net->lock, flags);
		node = riosocket_get_node_id(&net->actnodelist, destid);
		spin_unlock_irqrestore(&net->lock, flags);

		if (!node) {
			dev_info(&ndev->dev, "%s: node ptr = NULL\n", __func__);
			break;
		}

		rnet->rx_skb[i]->data = data;
		skb_put(rnet->rx_skb[i], msg_size);

		skb_queue_tail(&node->rx_queue, rnet->rx_skb[i]);
		napi_schedule(&node->napi);

	} while ((i = (i + 1) % RIONET_RX_RING_SIZE) != rnet->rx_slot);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
	return i;
}

static void riosocket_rx_fill(struct net_device *ndev, int end)
{
	int i;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	i = rnet->rx_slot;
	do {
		rnet->rx_skb[i] = dev_alloc_skb(RIO_MAX_MSG_SIZE);

		if (!rnet->rx_skb[i])
			break;

		rio_add_inb_buffer(rnet->mport, RIONET_MAILBOX,
				   rnet->rx_skb[i]->data);
	} while ((i = (i + 1) % RIONET_RX_RING_SIZE) != end);

	rnet->rx_slot = i;

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

static int riosocket_queue_tx_msg(struct sk_buff *skb, struct net_device *ndev,
			       struct riosocket_node *node, int count)
{
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	rio_add_outb_message(rnet->mport, node->rdev, 0, skb->data, skb->len);
	rnet->tx_skb[rnet->tx_slot] = skb;

	ndev->stats.tx_packets++;
	ndev->stats.tx_bytes += skb->len;

	++rnet->tx_cnt;

	++rnet->tx_slot;
	rnet->tx_slot &= (RIONET_TX_RING_SIZE - 1);

	if (count)
		atomic_inc(&skb->users);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

void riosocket_inb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot)
{
	int n;
	struct riosocket_network *net = dev_id;
	struct net_device *ndev = net->ndev;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;
	unsigned long flags;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	spin_lock_irqsave(&rnet->lock, flags);
	n = riosocket_rx_clean(net);
	if (n != rnet->rx_slot)
		riosocket_rx_fill(ndev, n);
	spin_unlock_irqrestore(&rnet->lock, flags);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

void riosocket_outb_msg_event(struct rio_mport *mport, void *dev_id, int mbox, int slot)
{
	struct net_device *ndev = dev_id;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	spin_lock(&rnet->tx_lock);

	while (rnet->tx_cnt && (rnet->ack_slot != slot)) {
		/* dma unmap single */

		atomic_dec(&priv->msg_pending);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0))
		dev_kfree_skb_irq(rnet->tx_skb[rnet->ack_slot]);
#else
		dev_consume_skb_irq(rnet->tx_skb[rnet->ack_slot]);
#endif
		rnet->tx_skb[rnet->ack_slot] = NULL;
		++rnet->ack_slot;
		rnet->ack_slot &= (RIONET_TX_RING_SIZE - 1);
		rnet->tx_cnt--;
	}

	spin_unlock(&rnet->tx_lock);
	tasklet_schedule(&priv->tx_tasklet);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
}

int riosocket_open(struct net_device *ndev)
{
	int i, rc = 0;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	/* Initialize inbound message ring */
	for (i = 0; i < RIONET_RX_RING_SIZE; i++)
		rnet->rx_skb[i] = NULL;

	rnet->rx_slot = 0;
	riosocket_rx_fill(ndev, 0);

	rnet->tx_slot = 0;
	rnet->tx_cnt = 0;
	rnet->ack_slot = 0;

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);
	return rc;
}

int riosocket_close(struct net_device *ndev)
{
	int i=0;
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	for (i = 0; i < RIONET_RX_RING_SIZE; i++)
			kfree_skb(rnet->rx_skb[i]);

	dev_dbg(&ndev->dev,"%s: End\n",__FUNCTION__);

	return 0;
}

int riosocket_start_xmit_msg(struct sk_buff *skb,
			     struct net_device *ndev, u16 destid)
{
	struct riosocket_private *priv = netdev_priv(ndev);
	struct riosocket_msg_private *rnet = &priv->rnetpriv;
	struct riosocket_node *node;
	unsigned long flags;
	int ret = NETDEV_TX_OK;

	dev_dbg(&ndev->dev,"%s: Start\n",__FUNCTION__);

	spin_lock_irqsave(&rnet->tx_lock, flags);

	if (destid == BROADCAST) {
		int count = 0;

		if ((rnet->tx_cnt + nets[priv->netid].nact)  > RIONET_TX_RING_SIZE) {
			ret = NETDEV_TX_BUSY;
			goto exit;
		}

		spin_lock(&nets[priv->netid].lock);
		list_for_each_entry(node,
				 &nets[priv->netid].actnodelist, nodelist) {

			if (node->ready) {
				dev_dbg(&ndev->dev,"%s: Sending broadcast message to node %d\n",
								__FUNCTION__,node->devid);
				riosocket_queue_tx_msg(skb, ndev, node, count);
				count++;
				atomic_inc(&priv->msg_pending);
			}
		}
		spin_unlock(&nets[priv->netid].lock);
	} else {

		if ((rnet->tx_cnt + 1)  > RIONET_TX_RING_SIZE) {
			ret = NETDEV_TX_BUSY;
			goto exit;
		}

		spin_lock(&nets[priv->netid].lock);
		node = riosocket_get_node_id(&nets[priv->netid].actnodelist,destid);
		spin_unlock(&nets[priv->netid].lock);

		if (node && node->ready) {
			dev_dbg(&ndev->dev,"%s: Sending message to node %d\n",__FUNCTION__,
										node->devid);
			riosocket_queue_tx_msg(skb, ndev, node, 0);
			atomic_inc(&priv->msg_pending);
		} else {
			dev_kfree_skb_irq(skb);
			ndev->stats.tx_dropped++;
		}
	}
exit:
	spin_unlock_irqrestore(&rnet->tx_lock,flags);
	dev_dbg(&ndev->dev, "%s: End ret=%d\n", __func__, ret);
	return ret;
}
