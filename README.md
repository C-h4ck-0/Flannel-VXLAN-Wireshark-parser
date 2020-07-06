# Flannel-VXLAN-Wireshark-parser
Flannel network plugin for Kubernetes VXLAN Lua parser for Wireshark



Wireshark allows the use of plugins written in Lua language.

Flannel - https://github.com/coreos/flannel, is a network plugin for Kubernetes using an VXLAN overlay network.
To simplify the process of understanding the Flannel communication protocol, I wrote a simple script that parses the relevant fields of the packet.

Parsing the packet by the definition of RFC 7348 - https://tools.ietf.org/html/rfc7348#page-10

Instructions to use this plugin (Ubuntu)
-----------------------------------------
1. Wireshark menu → Help → About Wireshark→ Folders
2. Save the script in the Global Plugins folder
3. Run Wireshark
4. Use “vxlan_flannel” as a filter
