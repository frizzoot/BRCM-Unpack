#!/bin/bash
#Install Dependencies: sudo apt install ugrep device-tree-compiler coreutils u-boot-tools gzip xz-utils
#############################START################################
#Color
if [ -t 1 ]; then
    r_c=$(tput setaf 1);    g_c=$(tput setaf 65);    y_c=$(tput setaf 214);    b_c=$(tput setaf 75);    n_c=$(tput sgr0)
else
    r_c="";    g_c="";    y_c="";    b_c="";    n_c=""
fi
#Log
log_file="output.log";exec > >(tee ${log_file}) 2>&1
#Check Files
source_file="$1"
if [ -z "$1" ]; then
  echo -e "$r_c"'Source File Not Specified'
  echo -e 'Usage: bash script.sh <sourcefile>'
  exit 1
fi
#Patterns
sqfs_pattern='hsqs';oldver_pattern='\x977\x00\x00\x00';fdt_pattern='\xD0\r\xFE\xED';kernel_kfst='IKCFG_ST';kernel_kfed='IKCFG_ED'
tr_clean="'/\-<>{};/\t\"\"\#'"
############################FDT##################################
total_bytes=$(wc -c < "$source_file")
if [ -n "$total_bytes" ]; then
	date=$(date)
    echo -e "$b_c"'Image Processing Started'"$n_c" on "$date" "$n_c";echo
    echo -e "$b_c"'Log'"$n_c": "$PWD"/"$log_file"
    echo -e "$b_c"'Source'"$n_c": "$PWD"/"$source_file"
    echo -e "$b_c"'Size'"$n_c": "$total_bytes";echo
else
	echo "Cannot read from '$source_file'";exit 1
fi
#Package Version Check
echo -e "$y_c"'Checking Package Version'"$n_c";echo
oldver_offset=$(ugrep -UXboum 1 $oldver_pattern "$source_file" | cut -d: -f1 -s)
if [ -n "$oldver_offset" ];then
    sqfs_offset=$(ugrep -UXboum 1 $sqfs_pattern "$source_file" | cut -d: -f1 -s)
    if [ "$sqfs_offset" -ge "$oldver_offset" ]; then
        root_name=${source_file%.*}
        root_sqfs="root_fs.sqfs"
        tail_bytes="$(("$total_bytes"-"$sqfs_offset"))"
        head --bytes="$total_bytes" "$source_file" | tail --bytes="$tail_bytes" > "$root_sqfs"
        echo -e "$b_c"'SQFS Offset'"$n_c": "$sqfs_offset"
        echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$root_sqfs";echo
    fi
fi
#FDT Pattern Matching, Head Chop and DTS conversion
echo -e "$y_c"'Checking for FDT Pattern'"$n_c";echo;pattern_offset=$(ugrep -UXboum 1 $fdt_pattern "$source_file" | cut -d: -f1 -s)
if [ -n "$pattern_offset" ];then
    if [ "$pattern_offset" -ge 1 ]; then
        root_name=${source_file%.*}
        root_dtb="$root_name"".dtb"
        tail_bytes="$(("$total_bytes"-"$pattern_offset"))"
        head --bytes="$total_bytes" "$source_file" | tail --bytes="$tail_bytes" > "$root_dtb"
        carved_bytes=$(wc -c < "$root_dtb")
        echo -e "$b_c"'FDT Offset'"$n_c": "$pattern_offset"
        echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$root_dtb"
        dtc -I dtb -O dts "$root_dtb" -o "$root_name".dts
        root_dts="$root_name".dts
        echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$root_dts";echo
    else
        echo -e "$b_c"'Skipping Head Removal'
        cp "$source_file" "$root_dtb"
        carved_bytes=$(wc -c < "$root_dtb")
        echo -e "$b_c"'Output Size: '"$carved_bytes"
    fi
else
  echo "Pattern not found in '$source_file'"
  exit 1
fi
#Root Description
root_props=$(fdtget -p "$root_dtb" /)
for prop in $root_props; do
    if [ "$prop" = description ];then
        description_data=$(fdtget -t s "$root_dtb" / description)
        echo -e "$b_c"'Description'"$n_c": "$description_data"
    fi
done
ident_count=$(fdtget -p "$root_dtb" / | grep -c "ident")
#Check for Ident
if [ "$ident_count" -gt 0 ];then
    next_ident='1'
    echo -e "$b_c"'Identity'"$n_c":
    until [ "$ident_count" -eq 0 ];do
        fdtget -tr "$root_dtb" / ident_"$next_ident" | tr -d '@()#$'
        next_ident="$((next_ident+2))"
        ident_count="$((ident_count-2))"
    done
fi
root_nodes=$(fdtget -l "$root_dtb" /);echo -e "$b_c"'Nodes'"$n_c": "$root_nodes" | tr '\n' ' ';echo
#Compatibility
for r_node in $root_nodes; do
    if [ "$r_node" = configurations ];then
    compatible=$(grep compatible "$root_dts" | tr ';' ' ' | awk '{$1=$1};1' | cut -d'"' -f 2)
    echo -e "$b_c"'Configuration'"$n_c": "$compatible"
    fi
    if [ "$r_node" = brcm_rootfs_encrypt ];then
        rfsencrypt_list=$(fdtget -p "$root_dtb" /brcm_rootfs_encrypt)
        echo;echo -e  "$y_c""Checking RootFS Encryption Node""$n_c";echo
        for rfs_prop in $rfsencrypt_list;do
        rfs_data=$(fdtget -ts "$root_dtb" /brcm_rootfs_encrypt/ "$rfs_prop")
        echo -e "$b_c""${rfs_prop^}""$n_c": "$rfs_data" | fold -s -w 100;echo
        done
    fi
    #Security
    if [ "$r_node" = security ];then
        security_list=$(fdtget -p "$root_dtb" /security)
        echo -e  "$y_c""Checking Security Node""$n_c";echo
        for sec_prop in $security_list;do
            if [ "$sec_prop" = data ];then
                echo -e  "$y_c""Extracting Embedded DTB Security Data""$n_c";echo
                fdtget -tr "$root_dtb" /security data > secblob.dtb
                dtc -I dtb -O dts secblob.dtb -o secblob.dts
                sec_pol=$(grep -A 7 security_policy secblob.dts | tr -d "$tr_clean")
                sec_roll=$(grep -A 5 anti-rollback secblob.dts | tr -d "$tr_clean")
                echo -e "$b_c"'Security Policy'"$n_c":;echo
                echo "$sec_pol" | tr -d '0x';echo
                echo -e "$b_c"'Anti Rollback Options'"$n_c":;echo
                echo "$sec_roll" | tr -d '0x';echo
                echo -e "$g_c"'Saved'"$n_c": "$PWD"/secblob.dts;echo
            fi
            if [ "$sec_prop" = signature ];then
                echo -e "$b_c"'Security Node Signature'"$n_c":;echo
                sec_sig=$(fdtget -tx "$root_dtb" /security "$sec_prop")
                echo "$sec_sig" | fold -s -w 72 ;echo
            fi
        done
    fi
    #Trust
    if [ "$r_node" = trust ]; then
        trust_list=$(fdtget -l "$root_dtb" /trust)
        echo -e "$b_c"'Trust'"$n_c": "$trust_list" | tr '\n' ' ';echo;echo
        key_list=$(fdtget -l "$root_dtb" '/trust/encoded_keys')
        key_count=$(echo "$key_list" | wc -l)
        if [ "$key_count" -gt 0 ]; then
            echo -e "$y_c"'Extracting Trust Node Salts and Keys'"$n_c";echo
            echo -e "$b_c"'Salts'"$n_c":;echo
            grep -B 2 -A 1 salt "$root_dts" | tr -d "$tr_clean" | tr -d '0x';echo
            echo -e "$b_c"'Encoded Keys':"$n_c"
            for key in $key_list; do
                key_description=$(fdtget -ts "$root_dtb" /trust/encoded_keys/"$key"/ description)
                key_algo=$(fdtget -ts "$root_dtb" /trust/encoded_keys/"$key"/ algo)
                key_name=$(fdtget -ts "$root_dtb" /trust/encoded_keys/"$key"/ key_name)
                echo;echo -e "$n_c"'Description'"$n_c": "$key_description"
                echo -e "$n_c"'Algo'"$n_c": "$key_algo"
                echo -e "$n_c"'Name'"$n_c": "$key_name"
                data_key=$(fdtget -p "$root_dtb" /trust/encoded_keys/"$key" | grep -c "data")
                if [ "$data_key" -eq 1 ]; then
                    key_data=$(fdtget -tx "$root_dtb" /trust/encoded_keys/"$key"/ data)
                    echo -e "$n_c"'Data'"$n_c": "$key_data"
                fi
            done
        fi
    fi
done
#Extract Images
for r_node in $root_nodes; do
    if [ "$r_node" = images ];then
        image_list=$(fdtget -l "$root_dtb" /images)
        echo -e "$b_c"'Images'"$n_c": "$image_list" | tr '\n' ' ';echo
        image_pos="0"
        for image in $image_list ;do
            echo;echo -e "$y_c"'Extracting'"$n_c""$n_c": "$image"
            dumpimage -p "$image_pos" -T flat_dt "$root_dtb" -o "$image" | sed -n '3,6p'
            file_info=$(file -pbsrz "$image")
            echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$image";echo
            image_pos="$((image_pos+1))"
            device_tree=$(echo "$file_info" | grep -sc "Device Tree Blob")
            #Check if DTB
            if [ "$device_tree" -gt 0 ]; then
                root_node=$(fdtget -p "$image" /)
                description_check=$(echo "$root_node" | grep "description")
                if [ -n "$description_check"  ]; then
                    description_data=$(fdtget -t s "$image" / description)
                    echo -e "$b_c"'Image Description'"$n_c": "$description_data"
                    dtc -I dtb -O dts "$image" -o "$image".dts
                    image_dts="$image".dts
                fi
                subnodes=$(fdtget -l "$image" /)
                echo -e  "$b_c"'Nodes'"$n_c": "$subnodes" | tr '\n' ' ';echo
                ident_count=$(fdtget -p "$image" / | grep -c "ident")
                #Check for Ident
                if [ "$ident_count" -gt 0 ];then
                    next_ident='1'
                    echo -e "$b_c"'Identity'"$n_c":
                    until [ "$ident_count" -eq 0 ];do
                        fdtget -tr "$image" / ident_"$next_ident" | tr -d '@()#$'
                        next_ident="$((next_ident+2))"
                        ident_count="$((ident_count-2))"
                    done
                fi
                #Process Subnodes
                for node in $subnodes; do
                    if [ "$node" = brcm_rootfs_encrypt ];then
                        rfsencrypt_list=$(fdtget -p "$image" /brcm_rootfs_encrypt)
                        echo;echo -e  "$y_c""Checking RootFS Encryption Node""$n_c";echo
                        for rfs_prop in $rfsencrypt_list;do
                        rfs_data=$(fdtget -ts "$image" /brcm_rootfs_encrypt/ "$rfs_prop")
                        echo -e "$b_c""${rfs_prop^}""$n_c": "$rfs_data" | fold -s -w 100;echo
                        done
                    fi
                    #Security
                    if [ "$node" = security ];then
                        security_list=$(fdtget -p "$image" /security)
                        echo -e  "$y_c""Checking Security Node""$n_c";echo
                            for sec_prop in $security_list;do
                                if [ "$sec_prop" = data ];then
                                    echo -e  "$y_c""Extracting Embedded DTB Security Data""$n_c";echo
                                    fdtget -tr "$image" /security data > secblob.dtb
                                    dtc -I dtb -O dts secblob.dtb -o secblob.dts
                                    sec_pol=$(grep -A 7 security_policy secblob.dts | tr -d "$tr_clean")
                                    sec_roll=$(grep -A 5 anti-rollback secblob.dts | tr -d "$tr_clean")
                                    echo -e "$b_c"'Security Policy'"$n_c":;echo
                                    echo "$sec_pol" | tr -d '0x';echo
                                    echo -e "$b_c"'Anti Rollback Options'"$n_c":;echo
                                    echo "$sec_roll" | tr -d '0x';echo
                                    echo -e "$g_c"'Saved'"$n_c": "$PWD"/secblob.dts;echo
                                fi
                                if [ "$sec_prop" = signature ];then
                                    echo -e "$b_c"'Security Node Signature'"$n_c":;echo
                                    sec_sig=$(fdtget -tx "$image" /security "$sec_prop")
                                    echo "$sec_sig" | fold -s -w 72 ;echo
                                fi
                            done
                    fi
                    #Subimages
                    if [ "$node" = images ]; then
                        echo -e  "$y_c""Checking Image Node""$n_c";echo
                        subimage_list=$(fdtget -l "$image" /images)
                        subimage_pos="0"
                        echo -e  "$b_c"'Images'"$n_c": "$subimage_list" | tr '\n' ' ';echo;echo
                        for subimage in $subimage_list; do
                            echo -e "$y_c"'Extracting'"$n_c""$n_c": "$subimage"
                            dumpimage -p "$subimage_pos" -T flat_dt "$image" -o "$subimage" | sed -n '3,6p'
                            echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$subimage";echo
                            subimage_pos="$((subimage_pos+1))"
                            file_info=$(file -pbsrz "$subimage")
                            device_tree=$(echo "$file_info" | grep -sc "Device Tree Blob")
                            if [ "$device_tree" -gt 0 ]; then
                                subroot_node=$(fdtget -p "$subimage" /)
                                description_check=$(echo "$subroot_node" | grep "description")
                                if [ -n "$description_check"  ]; then
                                    description_data=$(fdtget -ts "$subimage" / description)
                                    echo -e "$b_c"'Description'"$n_c": "$description_data"
                                    dtc -I dtb -O dts "$subimage" -o "$subimage".dts
                                    subimage_dts="$subimage".dts
                                    echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$subimage_dts";echo
                                fi
                            fi
                        done
                    fi
                    #Trust
                    if [ "$node" = trust ]; then
                        trust_list=$(fdtget -l "$image" /trust)
                        echo -e "$b_c"'Trust'"$n_c": "$trust_list" | tr '\n' ' ';echo;echo
                        key_list=$(fdtget -l "$image" '/trust/encoded_keys')
                        key_count=$(echo "$key_list" | wc -l)

                        if [ "$key_count" -gt 0 ]; then
                            echo -e "$y_c"'Extracting Trust Node Salts and Keys'"$n_c";echo
                            echo -e "$b_c"'Salts'"$n_c":;echo
                            grep -B 2 -A 1 salt "$image_dts" | tr -d "$tr_clean" | tr -d '0x';echo
                            echo -e "$b_c"'Encoded Keys':"$n_c"
                            for key in $key_list; do
                                key_description=$(fdtget -ts "$image" /trust/encoded_keys/"$key"/ description)
                                key_algo=$(fdtget -ts "$image" /trust/encoded_keys/"$key"/ algo)
                                key_name=$(fdtget -ts "$image" /trust/encoded_keys/"$key"/ key_name)
                                echo;echo -e "$n_c"'Description'"$n_c": "$key_description"
                                echo -e "$n_c"'Algo'"$n_c": "$key_algo"
                                echo -e "$n_c"'Name'"$n_c": "$key_name"
                                data_key=$(fdtget -p "$image" /trust/encoded_keys/"$key" | grep -c "data")
                                if [ "$data_key" -eq 1 ]; then
                                    key_data=$(fdtget -tx "$image" /trust/encoded_keys/"$key"/ data)
                                    echo -e "$n_c"'Data'"$n_c": "$key_data"
                                fi
                            done
                        fi
                    fi
                done
            fi
        done
    fi
done
date=$(date);echo -e "$b_c""Finished Image Processing\033[0m": "$date"; echo
###########################KERNEL##################################
echo -e "$b_c"'Started Kernel Processing'"$n_c": "$date"
if test -f "$PWD"/"kernel"; then
    kernel_file=$(file -b kernel);echo
    lzma_check=$(echo "$kernel_file" | grep -c "LZMA")
    if [ "$lzma_check" -eq 1 ]; then
        kernel_info=$(dumpimage -l "$root_dtb" | grep -h -A 11 --color=never '(kernel)')
        info_check=$(echo "$kernel_info" | grep "Kernel" -c)
        if [ "$info_check" -le 0 ];then
            kernel_info=$(dumpimage -l bootfs* | grep -h -A 11 --color=never '(kernel)')
        fi
        echo -e "$b_c"'Kernel Image Information'"$n_c":;echo "$kernel_info";echo
        echo -e "$y_c"'Decompressing Kernel'"$n_c";echo
        unlzma -dkc kernel > kernel.bin
        lzma_verify=$(file kernel.bin | grep "Linux kernel ARM64")
#Check For KConfig GZIP
        if [ -n "$lzma_verify" ]; then
            mv kernel kernel.lzma
            k_file='kernel.bin'
            kernel_bininfo=$(file -b "$k_file")
            kernel_bytes=$(wc -c < "$k_file")
            echo -e "$b_c"'File Information'"$n_c": "$kernel_bininfo"
            echo -e "$b_c"'Size'"$n_c": "$kernel_bytes"
            echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$k_file"; echo
            echo -e "$y_c"'Checking for Kernel Configuration'"$n_c";echo
            kfgst_offset=$(ugrep -UXboum 1 "$kernel_kfst" kernel.bin | cut -d: -f1 -s)
            kfged_offset=$(ugrep -UXboum 1 "$kernel_kfed" kernel.bin | cut -d: -f1 -s)
            if [ "$kfgst_offset" -gt 0 ]; then
                kfgst_bytes="$(("$kfgst_offset"+"8"))"
                ikcfg_tail="$(("$kfged_offset"-"$kfgst_bytes"))"
                head --bytes="$kfged_offset" "$k_file" | tail --bytes="$ikcfg_tail" > "kconfig.gz"
                gzip_check=$(file kconfig.gz | grep -c "gzip compressed data")
            else
                echo -e "$r_c"'Could Not Locate Gzip Compressed Kernel Configuration in '$k_file''
            fi
#Extract KConfig GZIP
                if [ "$gzip_check" -eq 1 ]; then
                    kconfig_gz='kconfig.gz'
                    echo -e "$b_c"'Offset'"$n_c": "$kfgst_offset"-"$kfged_offset"
                    echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$kconfig_gz"; echo
                    echo -e "$y_c"'Decompressing Kernel Configuration'"$n_c";echo
                    gunzip -kc kconfig.gz > kconfig.conf
                    kconf_check=$(file kconfig.conf | grep -c "Linux make config")
                    if [ "$kconf_check" -eq 1 ]; then
                        k_conf='kconfig.conf'
                        config_head=$(head -7 "$k_conf" | sed -n 's/^..//;3p;7p')
                        echo -e "$b_c"'Configuration Information'"$n_c":
                        echo "$config_head"
                        echo -e "$g_c"'Saved'"$n_c": "$PWD"/"$k_conf";echo
                    else
                        echo -e "$r_c"'Kernel Configuration Extraction Failed'"$n_c";
                    fi
                fi
        else
            echo -e "$r_c"'Kernel Extraction Failed'"$n_c"
        fi
    fi
fi
date=$(date);echo -e "$b_c"'All Processing Completed'"$n_c" on "$date";exit 1
#############################END################################