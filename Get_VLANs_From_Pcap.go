// That scripts is getting pools of addresses for each vlan in pcap dump
// Usage: go run script.go some.pcap

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Address struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

type PoolVLAN struct {
	Id        uint16    `json:"vlan"`
	Addresses []Address `json:"addrs"`
}

var (
	pcapFile string = os.Args[1]
	handle   *pcap.Handle
	err      error
)

func EqualMac(x net.HardwareAddr, y net.HardwareAddr) bool {
	if len(y) == len(x) {
		return bytes.Equal(y, x)
	}
	return false
}

func findPoolbyId(pools []PoolVLAN, id uint16) int {
	for i, pool := range pools {
		if pool.Id == id {
			return i
		}
	}
	return -1
}

func checkMACIsUnicast(mac net.HardwareAddr) bool {
	m1, _ := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	m2, _ := net.ParseMAC("01:80:C2:00:00:00")
	m3, _ := net.ParseMAC("00:00:00:00:00:00")
	not_unicast := []net.HardwareAddr{m1, m2, m3}

	for _, nu := range not_unicast {
		if EqualMac(mac, nu) {
			return false
		}
	}

	return true
}

func addAddr2Pool(pool *PoolVLAN, address Address) bool {
	mac, _ := net.ParseMAC(address.MAC)
	if checkMACIsUnicast(mac) {
		if len(pool.Addresses) > 0 {
			for i := range pool.Addresses {
				if pool.Addresses[i].MAC == address.MAC && pool.Addresses[i].IP == address.IP {
					return false
				}
			}
		}
		log.Printf("Adding new mac %s\n", mac)
		pool.Addresses = append(pool.Addresses, Address{address.MAC, address.IP})
		return true
	}
	return false
}

func main() {
	logfile, err := os.OpenFile("info.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer logfile.Close()
	log.SetOutput(logfile)

	handle, err = pcap.OpenOffline(pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	pools := []PoolVLAN{}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		vlan_layer := packet.Layer(layers.LayerTypeDot1Q)
		if vlan_layer != nil {
			vlan := vlan_layer.(*layers.Dot1Q)

			ethernet_layer := packet.Layer(layers.LayerTypeEthernet)
			ethernet_frame := ethernet_layer.(*layers.Ethernet)
			mac_src := net.HardwareAddr.String(ethernet_frame.SrcMAC)
			mac_dst := net.HardwareAddr.String(ethernet_frame.DstMAC)

			network_layer := packet.Layer(layers.LayerTypeIPv4)
			ip_src := ""
			ip_dst := ""
			if network_layer != nil {
				ipv4, _ := network_layer.(*layers.IPv4)
				ip_src = net.IP.String(ipv4.SrcIP)
				ip_dst = net.IP.String(ipv4.DstIP)
			}

			poolIndex := findPoolbyId(pools, vlan.VLANIdentifier)
			if poolIndex != -1 {
				addAddr2Pool(&pools[poolIndex], Address{mac_src, ip_src})
				addAddr2Pool(&pools[poolIndex], Address{mac_dst, ip_dst})
			} else {
				log.Printf("Adding new vlan %d with macs: %s, %s\n", vlan.VLANIdentifier, ethernet_frame.SrcMAC, ethernet_frame.DstMAC)
				pools = append(pools, PoolVLAN{Id: vlan.VLANIdentifier, Addresses: []Address{}})
				addAddr2Pool(&pools[findPoolbyId(pools, vlan.VLANIdentifier)], Address{mac_src, ip_src})
				addAddr2Pool(&pools[findPoolbyId(pools, vlan.VLANIdentifier)], Address{mac_src, ip_dst})
			}
		}
	}

	sort.Slice(pools, func(i, j int) bool { return pools[i].Id < pools[j].Id })
	for poolIndex := range pools {
		sort.Slice(pools[poolIndex].Addresses, func(i, j int) bool { return pools[poolIndex].Addresses[i].MAC < pools[poolIndex].Addresses[j].MAC })
	}

	JSON, err := json.Marshal(pools)
	if err != nil {
		log.Println("error:", err)
	} else {
		fmt.Println(string(JSON))
	}

}
