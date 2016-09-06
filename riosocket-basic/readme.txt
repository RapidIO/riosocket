RIOSocket-Basic (with IDT updates) Installation Instructions
============================================================

This document is an updated version of the original README.TXT file provided
by Centaurus Computing. It was modified to provide details about updates made
by IDT to the original driver code. Therefore some of features and parameters
described in this document may be different or unavailable in the original
device driver.

I. Linux Kernel Compatibility
-----------------------------

RIOSocket-Basic driver is compatible with Linux kernel v4.6 or newer, provided
that kernel is built with RapidIO subsystem support enabled including standard
kernel DMA Engine interface for RapidIO.

Many existing Linux distributions do not include RapidIO support by default. In
these cases end users have to configure and build RapidIO-capable custom version
of the Linux kernel supplied for their distribution. Below is a list of
available RapidIO configuration options (set to build as modules, but can be
configured as "built-in"). Config options marked with "*" must be enabled.

    CONFIG_RAPIDIO=m (*)
    CONFIG_RAPIDIO_TSI721=m (*)
    CONFIG_RAPIDIO_DISC_TIMEOUT=30
    CONFIG_RAPIDIO_ENABLE_RX_TX_PORTS=y (*)
    CONFIG_RAPIDIO_DMA_ENGINE=y (*)
    CONFIG_RAPIDIO_ENUM_BASIC=m
    CONFIG_RAPIDIO_TSI57X=m
    CONFIG_RAPIDIO_CPS_XX=m
    CONFIG_RAPIDIO_TSI568=m
    CONFIG_RAPIDIO_CPS_GEN2=m
    CONFIG_RAPIDIO_CPS_GEN3=m

In most cases building custom kernel with RapidIO enabled is not the best option
from long term maintenance point of view. To avoid this route it is recommended
to use "out-of-tree" RapidIO driver package that is available to download
from https://github.com/RapidIO/kernel-rapidio.

This driver package includes all most recent RapidIO subsystem code from
the mainline Linux kernel and may add some the most recent updates that will
be submitted to the mainline code.

NOTE: Using OOT RapidIO driver package is the preferred method supported by
riosocket driver build process.

II. PLatform Preparation
------------------------

1: Build and install RapidIO capable kernel v4.6  or newer (with config options
   shown above) and configure the kernel RapidIO subsystem as described in
   file Documentation/rapidio/rapidio.txt in kernel source code tree for
   selected version.

   OR

   If using a standard distribution with kernel version >= 3.10 without
   wanting to rebuild the original Linux kernel download, build and install
   OOT RapidIO driver package "kernel-rapidio" referenced above (see README file
   provided with the package). It is recommended to create a separate directory
   where "kernel-rapidio" will be unpacked (<INST_DIR> further in this text).

2: Append the following parameters to kernel boot command line see note about
   memory reservation below):

   On x86 platform: "net.ifnames=0 biosdevname=0 memmap=256M$1G"

   On PowerPc platform: "net.ifnames=0 biosdevname=0 mem=120G"

   NOTE: Memory reservation options should be adjusted by the user as required
   for each given platform. Boot command line option "memmap=" is not available
   on PowerPC platforms, therefore the option "mem=" should be used. Amount of
   memory defined by "mem=" should be set depending on available physical memory
   on each node. See file "Documentation/kernel-parameters.txt" in the Linux
   kernel source code tree.

   To automatically apply these command line options when updating the kernel
   edit GRUB_CMDLINE_LINUX configuration line in /etc/default/grub file:
   add "net.ifnames=0 biosdevname=0 memmap=256M\\\$1G" (or "mem=" version).
   After saving the changes execute command:
   "grub2-mkconfig -o /boot/grub2/grub.cfg".
   If required adjust this command for EFI boot.

3: Disable network manager by executing the following commands (depending on
   your Linux distribution):

   service NetworkManager stop
   chkconfig NetworkManager off

   or:

   systemctl stop NetworkManager.service
   systemctl disable NetworkManager.service

   Network interface configuration scripts should be adjusted accordingly.
   Network service has to be started and enabled as well.

III. Build and Install RIOSOCKET Driver
---------------------------------------

1: Unpack riosocket driver package into the installation direstory <RIO_INST>.

2: Make sure that "kernel-rapidio" driver package is installed in the same
   directory. If necessary build and install "kernel-rapidio" driver package.

3: If "kernel-rapidio" directory was unpacked with an additional release version
   suffix added to its name, rename it to "kernel-rapidio" or (better) create a
   symbolic link using following command: "ln -s <package_dir> kernel-rapidio".

4: Enter <RIO_INST>/riosocket-<version>/riosocket-basic directory and build the
   riosocket device driver by typing commands "make clean; make all".
   Install the driver using "sudo make install" command.
   Edit /etc/modprobe.d/riosocket.conf file to provide parameters matching to
   reserved memory configuration set in step 2 above.

2: Reboot the system.

IV. Using RIOSOCKET Driver
--------------------------

1: After the system boot enumerate the RapidIO network using one of methods that
   is applicable to your platform configuration.
   For example, use one of the following commands:
     "echo -1 > /sys/bus/rapidio/scan", OR
     "modprobe rio-scan scan=1""

   Usually application level software provides set of scripts that simplify
   this task.

2: Confirm the nodes are detected by checking for devices in following path:

   "ls /sys/bus/rapidio/devices"

3: On each node:
   - load riosocket device driver using the following command:

      "modprobe riosocket"

   - enter the riosocket-basic directory and execute performance tuning script:
      ./perf.sh 

     If there is no irqbalance daemon running the perf.sh utility will report an 
     error which can be safely ignored.

4: After execution of step 3, a new network device named rsock0 will appear on
    executing ifconfig -a command. From this point onward, the rsock0 can be used
    as any other Ethernet interface. Assign IP address to rsock0 and ping to others
    nodes:

    ifconfig rsock0 10.12.10.1 up
    ping 10.12.10.2

    PLease note that RIOSOCKET driver uses different data transmission modes
    depending on a packet size. For packets that have size less than message
    watermark value (defined as DEFAULT_MSG_WATERMARK=256 in riosocket.h) the
    driver will use RapidIO MBOX messaging, for larger packets DMA transfers.
    To ensure that ping command tests right packet transfer mode specify packet
    size using "-s" option. For example command "ping -s 8000 10.12.10.2" will
    transmit 8008 bytes using DMA.

5: To measure throughput, download/install iperf utility from
    http://sourceforge.net/projects/iperf/ version 2.0.5 and execute the following
    command:

    Server : iperf -s -fM
    Client : iperf -c <<Server IP>> -fM -i 1

    The expected throughput for the first cut of the s/w is 1.2...1.7 GBytes/sec for
    Gen2 5Gbps * 4 link.

V. Driver Configuration Parameters
----------------------------------

1: rio_phys_mem - Physical base address of reserved memory space. This address
   is defined by boot command line parameter "memmap=" or "mem=".
   For example:
   a. if reserved memory space is defined using boot command line parameter
      "memmap=256M$1G", physical base address will be located at 1G boundary,
      or at 0x40000000. Size of the reserved space will be 256M
   b. if reserved memory space is defined using boot command line parameter
      "mem=129G" on POWER8 machine with 128GB of memory, physical base address
      will be locates at 120GB boundary, or at 0x1e00000000. Size of reserved
      memory can be used up to 8GB.

2: rio_phys_size - Size of reserved memory space. See base address parameter
   examples above. The size of memory required by the device driver is defined
   by number of RapidIO nodes forming the network and number of networks.
   By default each node requires 2MB of memory. Default number of nodes per
   network is 64. As result each adapter requires 128MB of memory.

3: rio_base_addr - Base address of RapidIO inbound window.
   Because RapidIO address exchange protocol between nodes can support physical
   memory address within first 16GB of address space, PowerPC platforms with
   the system memory larger than 16GB require buffer address to be mapped within
   first 16GB on RapidIO side. By default this parameter is set to 0 on all
   platforms. If there is a conflict with other drivers adjustment of this
   parameter provides some flexibility in a system configuration.

4: rio_ibw_size - Inbound mapping window size for each network/adapter. Defines
   size of memory block from the reserved space assigned to each rsock adapter.
   Default size is 128MB, this is equal to 64 nodes (2MB per node).

5: rio_db - RapidIO doorbell base address. Defines base value for doorbell range
   used by the device driver to initialize, maintain and terminate communication
   between nodes.
