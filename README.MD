## Broadcom Firmware Image Unpacker ##

### Introduction ###

This bash script is used to assist with the unpacking of a Broadcom firmware update package. 

Tested on Ubuntu 24.04 with firmware for a NOKIA BGW320-505 Residential Gateway.

**This script should work with all firmware versions as of writing.**

*Fixed issue with old version pattern Oct 18 24.

**The SquashFS is encrypted on current versions.**

**This script does not attempt to decrypt any information.**

**Root permissions are NOT necessary to run this script.**

## Features ##

Attempts to identify, extract, decompress & analyze the following:

	- Device Tree Blob / File Device Tree
	- Embedded Images & Nodes
	- Image Package Version, Description & Identity Information
	- Kernel Information & Build Configuration
	- Image Security Policy
	- Embedded Salts & Keys
	- Root Filesystem Image
	- Device Mapper Configuration
	
 
### Example Usage ###

Example Image Name: "spTurquoise320-505_6.28.7_sec.bin"

Install Dependencies:
```
sudo apt-get ugrep device-tree-compiler coreutils u-boot-tools gzip xz-utils
```

Check Permissions:
```
sudo chown user:user spTurquoise320-505_6.28.7_sec.bin
```
Run Script:
```
./unpack.sh spTurquoise320-505_6.28.7_sec.bin
```

### Example Terminal Output ###

<pre><font color="#5FAFFF">Image Processing Started</font> on Sat Oct  5 12:49:36 PM EDT 2024 

<font color="#5FAFFF">Log</font>: /home/user/unpack/output.log
<font color="#5FAFFF">Source</font>: /home/user/unpack/spTurquoise320-505_6.28.7_sec.bin
<font color="#5FAFFF">Size</font>: 89331668

<font color="#FFAF00">Checking Package Version</font>

<font color="#FFAF00">Checking for FDT Pattern</font>

<font color="#5FAFFF">FDT Offset</font>: 3336
<font color="#5F875F">Saved</font>: /home/user/unpack/spTurquoise320-505_6.28.7_sec.dtb
<font color="#5F875F">Saved</font>: /home/user/unpack/spTurquoise320-505_6.28.7_sec.dts

<font color="#5FAFFF">Description</font>: Broadcom BCA image upgrade package tree binary
<font color="#5FAFFF">Nodes</font>: images configurations 
<font color="#5FAFFF">Configuration</font>: flash=emmc chip=6858 rev=b0+ ip=ipv6,ipv4 ddr=ddr3 fstype=squashfs profile=BGW320-505
<font color="#5FAFFF">Images</font>: bootfs_6858_b0+ emmc_squashfs 

<font color="#FFAF00">Extracting</font>: bootfs_6858_b0+
  Description:  bootfs
  Created:      Thu Jul 11 21:47:49 2024
  Type:         Multi-File Image
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/bootfs_6858_b0+

<font color="#5FAFFF">Image Description</font>: Simple image with ATF and optional OP-TEE support
<font color="#5FAFFF">Nodes</font>: trust brcm_rootfs_encrypt security images configurations 
<font color="#5FAFFF">Identity</font>:
 imageversion: 5044p2BGW320-5051940145 
 imgversion: 5.04L.04p2 
 image_version: 6.28.7 
 image_ident: 006.028.007 
 swverforuboot: 006.028.007 
<font color="#5FAFFF">Trust</font>: anti-rollback hw_state encoded_keys sec_exports 

<font color="#FFAF00">Extracting Trust Node Salts and Keys</font>

<font color="#5FAFFF">Salts</font>:

item_name = key_dev_specific_256
algo = sha256
salt = EXAMPLE
length = 2

item_name = key_dev_specific_512
algo = sha256
salt = EXAMPLE
length = 4

item_name = key_rpmb_auth
algo = sha256
salt = EXAMPLE
length = 2

<font color="#5FAFFF">Encoded Keys:</font>

Description: OPTEE Key
Algo: aes-cbc-128
Name: optee_aes
Data: EXAMPLE

Description: Image decryption Key
Algo: aes-cbc-128
Name: image_aes
Data: EXAMPLE

Description: Bootloader CLI Key seed
Algo: aes-cbc-128
Name: cli_seed

Description: rpmb authentication key for provisioning image
Algo: aes-cbc-128
Name: rpmb_auth

Description: mascert key
Algo: aes-cbc-128
Name: mascert_key
Data: EXAMPLE

<font color="#FFAF00">Checking RootFS Encryption Node</font>

<font color="#5FAFFF">Mapper</font>: EXAMPLE

<font color="#5FAFFF">Dev</font>: EXAMPLE

<font color="#5FAFFF">Type</font>: squashfs

<font color="#FFAF00">Checking Security Node</font>

<font color="#FFAF00">Extracting Embedded DTB Security Data</font>

<font color="#5FAFFF">Security Policy</font>:

security_policy 
delegate_id = 1
min_tpl_compatibility = 2

keyaes 
description = Encrypted AES key  Mandatory Node
data = EXAMPLE
algo = aescbc128

<font color="#5FAFFF">Anti Rollback Options</font>:

antirollback 
status = enabled
description = Antirollback update  Optional Node
new_antirollback = 5
antirollback_limit = f

<font color="#5F875F">Saved</font>: /home/user/unpack/secblob.dts

<font color="#5FAFFF">Security Node Signature</font>:

EXAMPLE

<font color="#FFAF00">Checking Image Node</font>

<font color="#5FAFFF">Images</font>: atf optee uboot fdt_uboot kernel fdt_BGW320_500 fdt_BGW320_505 

<font color="#FFAF00">Extracting</font>: atf
  Description:  ATF
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Firmware
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/atf

<font color="#FFAF00">Extracting</font>: optee
  Description:  OPTEE
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Unknown Image
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/optee

<font color="#FFAF00">Extracting</font>: uboot
  Description:  U-Boot
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Unknown Image
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/uboot

<font color="#FFAF00">Extracting</font>: fdt_uboot
  Description:  dtb
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Flat Device Tree
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/fdt_uboot

<font color="#FFAF00">Extracting</font>: kernel
  Description:  Linux kernel
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Kernel Image
  Compression:  lzma compressed
<font color="#5F875F">Saved</font>: /home/user/unpack/kernel

<font color="#FFAF00">Extracting</font>: fdt_BGW320_500
  Description:  dtb
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Flat Device Tree
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/fdt_BGW320_500

<font color="#FFAF00">Extracting</font>: fdt_BGW320_505
  Description:  dtb
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Flat Device Tree
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/fdt_BGW320_505


<font color="#FFAF00">Extracting</font>: emmc_squashfs
  Description:  rootfs
  Created:      Thu Jul 11 21:47:49 2024
  Type:         Filesystem Image
  Compression:  uncompressed
<font color="#5F875F">Saved</font>: /home/user/unpack/emmc_squashfs

<font color="#5FAFFF">Finished Image Processing</font>: Sat Oct  5 12:49:38 PM EDT 2024

<font color="#5FAFFF">Started Kernel Processing</font>: Sat Oct  5 12:49:38 PM EDT 2024

<font color="#5FAFFF">Kernel Image Information</font>:
 Image 4 (kernel)
  Description:  Linux kernel
  Created:      Thu Jul 11 21:47:05 2024
  Type:         Kernel Image
  Compression:  lzma compressed
  Data Size:    3281971 Bytes = 3205.05 KiB = 3.13 MiB
  Architecture: AArch64
  OS:           Linux
  Load Address: 0x01000000
  Entry Point:  0x01000000
  Hash algo:    sha256
  Hash value:   EXAMPLE

<font color="#FFAF00">Decompressing Kernel</font>

<font color="#5FAFFF">File Information</font>: Linux kernel ARM64 boot executable Image, little-endian, 4K pages
<font color="#5FAFFF">Size</font>: 9496584
<font color="#5F875F">Saved</font>: /home/user/unpack/kernel.bin

<font color="#FFAF00">Checking for Kernel Configuration</font>

<font color="#5FAFFF">Offset</font>: 7004216-7028790
<font color="#5F875F">Saved</font>: /home/user/unpack/kconfig.gz

<font color="#FFAF00">Decompressing Kernel Configuration</font>

<font color="#5FAFFF">Configuration Information</font>:
Linux/arm64 4.19.275 Kernel Configuration
Compiler: EXAMPLE
<font color="#5F875F">Saved</font>: /home/user/unpack/kconfig.conf

<font color="#5FAFFF">All Processing Completed</font> on Sat Oct  5 12:49:38 PM EDT 2024</pre>

## Example File Output List ##

<pre>-rw------- 1 user user  49K Oct  5 12:49 atf
-rw------- 1 user user 7.7M Oct  5 12:49 bootfs_6858_b0+
-rw-rw-r-- 1 user user  11K Oct  5 12:49 bootfs_6858_b0+.dts
-rw------- 1 user user  78M Oct  5 12:49 emmc_squashfs
-rw------- 1 user user  69K Oct  5 12:49 fdt_BGW320_500
-rw------- 1 user user  67K Oct  5 12:49 fdt_BGW320_505
-rw------- 1 user user 6.9K Oct  5 12:49 fdt_uboot
-rw-rw-r-- 1 user user 105K Oct  5 12:49 kconfig.conf
-rw-rw-r-- 1 user user  24K Oct  5 12:49 <font color="#C01C28"><b>kconfig.gz</b></font>
-rw-rw-r-- 1 user user 9.1M Oct  5 12:49 kernel.bin
-rw------- 1 user user 3.2M Oct  5 12:49 <font color="#C01C28"><b>kernel.lzma</b></font>
-rw------- 1 user user 732K Oct  5 12:49 optee
-rw-rw-r-- 1 user user 7.8K Oct  5 12:49 output.log
-rw-rw-r-- 1 user user 1.1K Oct  5 12:49 secblob.dtb
-rw-rw-r-- 1 user user 1.1K Oct  5 12:49 secblob.dts
-rw-rw-r-- 1 user user  86M Oct  5 12:30 spTurquoise320-505_6.28.7_sec.bin
-rw-rw-r-- 1 user user  86M Oct  5 12:49 spTurquoise320-505_6.28.7_sec.dtb
-rw-rw-r-- 1 user user 1.1K Oct  5 12:49 spTurquoise320-505_6.28.7_sec.dts
-rw-rw-r-- 1 user user  18K Oct  5 12:49 unpack.sh
-rw------- 1 user user 3.7M Oct  5 12:49 uboot</pre>
