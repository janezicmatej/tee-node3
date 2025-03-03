#!/bin/bash  

# Function to cleanup background processes on script exit  
cleanup() {  
    echo "Cleaning up background processes..."  
    kill $(jobs -p) 2>/dev/null  
    exit  
}  

# Set up trap to catch script termination  
trap cleanup EXIT  

# Array of client configs  
declare -a client_configs=(  
    "tests/configs/config_client.toml"  
    "tests/configs/config_client2.toml"  
    "tests/configs/config_client3.toml"  
)  

tee_ids=()
pub_keys=()

# Run initial policy simulate for each client config  
for i in "${!client_configs[@]}"; do  

    config="${client_configs[$i]}" 

    node_info_json=$(<"tests/scripts/wallet/node_info.json")
 
    tee_ids=$(echo "$node_info_json" | jq '[.[].tee_id]')  


    # backup wallet
    instruction_id=$(shuf -i 1-1000000 -n 1)

#     # Create the RecoverInfo JSON  
# recover_info=$(jq -n \
#   --argjson tee_ids "$tee_ids" \
#   --arg pub_key "$pub_key" \
#   --arg address "$address" \
#   '{tee_ids: $tee_ids, pub_key: $pub_key, address: $address}')  

    for j in {0..1}; do   
        go run tests/client/cmd/main.go --call split_wallet --arg1 "$j" --arg2 foo --arg3 "$instruction_id" --arg4 "$backup_node_infos" --config "$config"   
    done


done  




