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


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/device.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/sysfs.h>

#include <linux/rio_drv.h>
#include <linux/rio_ids.h>

#include "riosocket.h"

unsigned long msgwatermark=DEFAULT_MSG_WATERMARK;

static ssize_t msgwatermark_show(struct device_driver *ddp, char *buf)
{
	  return snprintf(buf,PAGE_SIZE, "%ld\n", msgwatermark);
}

static ssize_t msgwatermark_store(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &msgwatermark)) {
		if( msgwatermark < 14 )
			msgwatermark=0;
		return count;
	} else {
		return 0;
	}
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
static DRIVER_ATTR(msgwatermark, S_IRUSR | S_IWUSR,
		msgwatermark_show, msgwatermark_store);
#else
static DRIVER_ATTR_RW(msgwatermark);
#endif

static ssize_t txringfull_show(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.txringfull);
}

static ssize_t txringfull_store(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.txringfull))
		return count;
	else
		return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
static DRIVER_ATTR(txringfull, S_IRUSR | S_IWUSR,
		txringfull_show, txringfull_store);
#else
static DRIVER_ATTR_RW(txringfull);
#endif


static ssize_t maxintransitpkt_show(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.maxintransitpkt);
}

static ssize_t maxintransitpkt_store(struct device_driver *ddp,
					const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.maxintransitpkt))
		return count;
	else
		return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
static DRIVER_ATTR(maxintransitpkt, S_IRUSR | S_IWUSR,
		maxintransitpkt_show, maxintransitpkt_store);
#else
static DRIVER_ATTR_RW(maxintransitpkt);
#endif


static ssize_t numxmitmore_show(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.numxmitmore);
}

static ssize_t numxmitmore_store(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.numxmitmore))
		return count;
	else
		return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
static DRIVER_ATTR(numxmitmore, S_IRUSR | S_IWUSR,
		numxmitmore_show, numxmitmore_store);
#else
static DRIVER_ATTR_RW(numxmitmore);
#endif

static ssize_t napisaturate_show(struct device_driver *ddp, char *buf)
{
         return snprintf(buf,PAGE_SIZE, "%ld\n", stats.napisaturate);
}

static ssize_t napisaturate_store(struct device_driver *ddp,
                                      const char *buf, size_t count)
{
	if(!kstrtoul(buf, 10, &stats.napisaturate))
		return count;
	else
		return 0;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0))
static DRIVER_ATTR(napisaturate, S_IRUSR | S_IWUSR,
		napisaturate_show, napisaturate_store);
#else
static DRIVER_ATTR_RW(napisaturate);
#endif

static struct attribute *riosocket_drv_attrs[] = {
        &driver_attr_txringfull.attr,
		&driver_attr_maxintransitpkt.attr,
		&driver_attr_numxmitmore.attr,
		&driver_attr_napisaturate.attr,
		&driver_attr_msgwatermark.attr,
		NULL
};

static struct attribute_group riosocket_drv_attr_grp = {
        .attrs = riosocket_drv_attrs
};

const struct attribute_group *riosocket_drv_attr_groups[] = {
        &riosocket_drv_attr_grp,
        NULL,
};
