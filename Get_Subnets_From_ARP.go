// This is a euristic algorithm to calculate minimum-acceptable subnet from the pairs of IP addresses in the ARP-Reply
//
// How to run: [go run] app filename
// You can pass a pcap binary dump or a plain-text file as input
// A text file should contain pair of IP addresses of the same ARP on each string and everything else will be ignored
/* Text input example:
┌─src───────────┬─dst────────────┬─protocol──┬─message────┐
│ 10.0.76.1     │ 10.0.76.2      │ ARP       │ ARP_Reply  │
│ 10.0.76.1     │ 10.0.77.100    │ ARP       │ ARP_Reply  │
│ 192.168.0.1   │ 192.168.0.12   │ ARP       │ ARP_Reply  │
│ 192.168.0.12  │ 192.168.0.13   │ ARP       │ ARP_Reply  │
│ 192.168.0.13  │ 192.168.0.18   │ ARP       │ ARP_Reply  │
│ 192.168.0.18  │ 192.168.0.1    │ ARP       │ ARP_Reply  │
└───────────────┴────────────────┴───────────┴────────────┘
*/
// On the output there is a JSON, containing array of subnet structs of attributes: label, network address, netmask and pool containing detected ip addresses

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Data structures
type Subnet struct {
	Label   string   `json:"label"`   // Human readable subnet label (10.10.10.0/24)
	Address net.IP   `json:"address"` // Network IP address (10.10.10.0)
	Mask    string   `json:"mask"`    // Netmask (255.255.255.0)
	Pool    []net.IP `json:"pool"`    // Array of IP addresses, communicating in that input
}

// Main vars
var (
	appname  string = os.Args[0]
	filename string = os.Args[1]
	handle   *pcap.Handle
	err      error
)

// Main
func main() {
	initLog(appname)

	subnets := []Subnet{}

	// Check if file is a text/plain
	fileType, err := GetFileContentType(filename)
	if err != nil {
		log.Fatal(err)
	}
	if strings.Contains(fileType, "text") {
		file, err := ioutil.ReadFile(filename)
		if err != nil {
			panic(err)
		}
		scanner := bufio.NewScanner(strings.NewReader(string(file)))
		for scanner.Scan() {
			ip_src, ip_dst := parseSrcDstAddesses(scanner.Text())
			if ip_src != nil && ip_dst != nil {
				subnets = fillSubnetPoolsWithIP(subnets, ip_src, ip_dst)
			}
		}
	} else { // Open file as pcap otherwise
		handle, err = pcap.OpenOffline(filename)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)

		for packet := range packetSource.Packets() {
			arp_layer := packet.Layer(layers.LayerTypeARP)
			if arp_layer != nil {
				arp := arp_layer.(*layers.ARP)
				if arp.Operation == 2 {
					subnets = fillSubnetPoolsWithIP(subnets, arp.SourceProtAddress, arp.DstProtAddress)
				}
			}
		}
	}

	for i, _ := range subnets {
		fillSubnetAddressByPoolRange(&subnets[i])
		subnets[i].Pool = uniquePool(subnets[i].Pool)
	}

	JSON, err := json.Marshal(subnets)
	if err != nil {
		fmt.Println("error:", err)
	} else {
		fmt.Println(string(JSON))
	}

}

// // Functions definition //////////////////////////////////////////////////////////////////
func GetFileContentType(filename string) (string, error) {
	// Open the file
	file, err := os.Open(filename)
	if err != nil {
		panic(err)
		return "", err
	}
	defer file.Close()
	// to sniff the content type only the first
	// 512 bytes are used.
	buf := make([]byte, 512)
	_, err = file.Read(buf)
	if err != nil {
		return "", err
	}
	// the function that actually does the trick
	contentType := http.DetectContentType(buf)
	return contentType, nil
}

func initLog(appname string) bool {
	logfile, err := os.OpenFile(appname+".log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logfile.Close()
	log.SetOutput(logfile)
	return true
}

func getSubnetByIP(subnets []Subnet, ip net.IP) int {
	subnet_index := -1
	for i, snet := range subnets {
		for _, sip := range snet.Pool {
			if sip.Equal(ip) {
				subnet_index = i
			}
		}
	}
	return subnet_index
}

func getDistanceBetweenIPv4(ip_min net.IP, ip_max net.IP) uint64 {
	var number_of_hosts uint64
	byte_slice_max := ip_max.To4()
	byte_slice_min := ip_min.To4()
	var ip_min_dec uint64
	var ip_max_dec uint64
	ip_min_dec = uint64(byte_slice_min[len(byte_slice_min)-1]) + 256*uint64(byte_slice_min[len(byte_slice_min)-2]) + 65536*uint64(byte_slice_min[len(byte_slice_min)-3]) + 16777216*uint64(byte_slice_min[len(byte_slice_min)-4])
	ip_max_dec = uint64(byte_slice_max[len(byte_slice_max)-1]) + 256*uint64(byte_slice_max[len(byte_slice_max)-2]) + 65536*uint64(byte_slice_max[len(byte_slice_max)-3]) + 16777216*uint64(byte_slice_max[len(byte_slice_max)-4])
	number_of_hosts = ip_max_dec - ip_min_dec + 1
	return number_of_hosts
}

func getMaskByHostsNumber(number_of_hosts uint64) int {
	// Host bits = ABS(Log2(Number-of-hosts))
	// Mask = 32 - 7 = 25
	host_bits := math.Ceil(math.Log2(float64(number_of_hosts)))
	result := 32 - int(host_bits)
	return result
}

func fillSubnetAddressByPoolRange(subnet *Subnet) *Subnet {
	// SUBNET = IP-ADDR AND NETMASK
	// BROADCAST = IP-ADDR OR (NOT(NETMASK))
	// NETMASK = find same substring(1), ignore rest(0)
	subnet.Pool = sortPool(subnet.Pool)
	ip_min := subnet.Pool[0]
	ip_max := subnet.Pool[len(subnet.Pool)-1]
	ip_distance := getDistanceBetweenIPv4(ip_min, ip_max)
	Mask_bits := getMaskByHostsNumber(ip_distance)
	netMask := net.CIDRMask(Mask_bits, 32)
	subnet_addr := ip_min.Mask(netMask)
	subnet.Label = subnet_addr.String() + "/" + strconv.Itoa(Mask_bits)
	subnet.Mask = net.IP(netMask).String()
	subnet.Address = subnet_addr
	return subnet
}

func removeSubnet(s []Subnet, i int) []Subnet {
	s[i] = s[len(s)-1]
	return s[:len(s)-1]
}

func sortPool(Pool []net.IP) []net.IP {
	sort.Slice(Pool, func(i, j int) bool {
		return bytes.Compare(Pool[i], Pool[j]) < 0
	})
	return Pool
}

func checkIpIsUnicast(ip net.IP) bool {
	not_unicast := []net.IP{
		net.ParseIP("255.255.255.255"),
		net.ParseIP("0.0.0.0"),
		net.ParseIP("127.0.0.1"),
		net.ParseIP("224.0.0.1"),
		net.ParseIP("224.0.0.2")}
	for _, nu := range not_unicast {
		if ip.Equal(nu) {
			return false
		}
	}
	return true
}

func uniquePool(Pool []net.IP) []net.IP {
	keys := make(map[string]bool)
	list := []net.IP{}
	for _, ip := range Pool {
		if _, value := keys[ip.String()]; !value {
			keys[ip.String()] = true
			list = append(list, ip)
		}
	}
	return list
}

func IsPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}

func parseSrcDstAddesses(input string) (net.IP, net.IP) {
	re_IP := regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)`)
	match := re_IP.FindAllStringSubmatch(input, 2)
	if match != nil {
		return net.ParseIP(match[0][0]), net.ParseIP(match[1][0])
	}
	return nil, nil
}

func fillSubnetPoolsWithIP(subnets []Subnet, ip_src net.IP, ip_dst net.IP) []Subnet {
	if checkIpIsUnicast(ip_src) && checkIpIsUnicast(ip_dst) { //&& !IsPublicIP(tmp_ip_src) && !IsPublicIP(tmp_ip_dst) {
		// Also check IPs is not BC or MC nor PublicIP
		if len(subnets) < 1 { // if subnets is empty
			// Creating first Pool
			subnets = append(subnets, Subnet{Pool: []net.IP{ip_src, ip_dst}})
		}
		with_src := getSubnetByIP(subnets, ip_src)
		with_dst := getSubnetByIP(subnets, ip_dst)

		if with_src == -1 && with_dst == -1 {
			// Creating a new Pool
			subnets = append(subnets, Subnet{Pool: []net.IP{ip_src, ip_dst}})
		} else if with_src != -1 && with_dst == -1 {
			// Adding ip_dst to Pool with ip_src
			subnets[with_src].Pool = append(subnets[with_src].Pool, ip_dst)
		} else if with_src == -1 && with_dst != -1 {
			// Adding ip_src to Pool with ip_src
			subnets[with_dst].Pool = append(subnets[with_dst].Pool, ip_dst)
		} else if with_src != -1 && with_dst != -1 && with_src != with_dst {
			// Merge two subnets
			subnets[with_src].Pool = append(subnets[with_src].Pool, subnets[with_dst].Pool...)
			// Remove excess Pool
			subnets = removeSubnet(subnets, with_dst)
		}
	}
	return subnets
}
