for fn in `openstack baremetal node list | awk -F '|' '{print $3}' | grep -v Name`; do touch "$fn.json"; done
for fn in `openstack baremetal node list | awk -F '|' '{print $3}' | grep -v Name`; do openstack baremetal introspection data save "$fn" | jq '.' > "$fn.json"; done

openstack baremetal introspection data save server-1 | jq '.' > server-1.jso
