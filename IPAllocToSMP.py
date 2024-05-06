# QUESTION:
# consider the case where a RIR has a list of AS's which are looking for new IP allocations, 
# and a list of IP address blocks which are ready to be allocated. Is it possible to allocate these
# in a way where you optimize network performance / security while not giving bias towards any
# of the AS's?

# SOLUTION: 
# Gale-Shapley?
# We can say that the Gale-shapley algorithm, in the worst case, will NEVER give us a worse pairing than a random pairing between IP blocks and AS's.
# On the average case, we can say that the Gale-Shapley algorithm will ALWAYS give us the max number of aggregatable pairs possible, given a list of AS's, and a lost of IP blocks.


import ipaddress
import random

#--------------------------------LIST GENERATIONS --------------------------

def random_ip(network):
    net = ipaddress.ip_network(network)
    return str(random.choice(list(net.hosts())))

def random_cidr(base_ip):
    prefix = random.choice(range(22, 30))  # Choosing a random CIDR between /22 and /29
    return f"{base_ip}/{prefix}"

def generate_as_ip_blocks(num_as, num_blocks):
    # Define some base networks to randomly pick from
    base_networks = ['10.0.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '198.51.100.0/24']
    
    # Generate Autonomous Systems
    autonomousSystems = {}
    for i in range(1, num_as + 1):
        base_net = random.choice(base_networks)
        base_ip = random_ip(base_net)
        cidr = random_cidr(base_ip)
        autonomousSystems[f'AS{i}'] = cidr

    # Generate IP Blocks
    ipBlocks = []
    for i in range(num_blocks):
        base_net = random.choice(base_networks)
        base_ip = random_ip(base_net)
        cidr = random_cidr(base_ip)
        ipBlocks.append(cidr)
    
    return autonomousSystems, ipBlocks


def count_aggregations(matchings, autonomousSystems):
    aggregations = 0
    for as_id, ip in matchings.items():
        as_cidr = autonomousSystems[as_id]
        if can_aggregate(as_cidr, ip):
            aggregations += 1
    return aggregations

#-----------------------------END---------------------------------------------




#--------------------AS PREFERENCE DETERMINATION------------------------------

# Determines if 2 blocks can be aggregated.
def can_aggregate(cidr1, cidr2):
    # Create network objects for both CIDR blocks
    network1 = ipaddress.ip_network(cidr1, strict=False)
    network2 = ipaddress.ip_network(cidr2, strict=False)
    
    # Check if either network is a supernet of the other
    if network1.supernet_of(network2) or network2.supernet_of(network1):
        return True
    
    # Calculate the smallest network that can contain both networks
    try:
        # Attempt to create a supernet that is one prefix length shorter than the larger of the two
        if network1.prefixlen > network2.prefixlen:
            smaller_prefix = network2.prefixlen
        else:
            smaller_prefix = network1.prefixlen
        
        # Create supernets and check if they are the same
        supernet1 = network1.supernet(new_prefix=smaller_prefix-1)
        supernet2 = network2.supernet(new_prefix=smaller_prefix-1)
        if supernet1 == supernet2:
            return True
    except ValueError:
        # If it fails (e.g., when trying to create a supernet beyond /0), return False
        pass
    
    return False




# Gets the LCP of 2 networks, in order to help with preference determination.
def get_common_prefix_length(net1, net2):
    # Convert network addresses to binary strings
    bin1 = bin(int(net1.network_address))[2:].zfill(net1.max_prefixlen)
    bin2 = bin(int(net2.network_address))[2:].zfill(net2.max_prefixlen)
    
    # Determine the longest common prefix length
    lcpl = 0
    for b1, b2 in zip(bin1, bin2):
        if b1 == b2:
            lcpl += 1
        else:
            break
    return lcpl



# ranks  ip blocks for a given AS, based on difference in prefix, and longest common prefix
def rank_ip_blocks_for_as(as_cidr, ip_blocks):
    # Convert the AS CIDR to a network object, correcting for host bits if necessary
    as_network = ipaddress.ip_network(as_cidr, strict=False)
    
    # Create a list of tuples (IP block, total score)
    ranking = []
    for ip in ip_blocks:
        # Correct each IP block for host bits if necessary
        ip_network = ipaddress.ip_network(ip, strict=False)
        
        # Calculate the aggregateability score based on CIDR prefix
        prefix_diff = abs(as_network.prefixlen - ip_network.prefixlen)
        aggregateability_score = 32 - prefix_diff  
        
        # Calculate network similarity score based on longest common prefix length
        lcpl = get_common_prefix_length(as_network, ip_network)
        
        # Summing up scores: prioritize networks with higher LCPL and similar prefix length
        total_score = (lcpl * 2) + aggregateability_score  # Weight LCPL more
        
        ranking.append((ip, total_score))
    
    # Sort the list of tuples by the second item (total score), descending order
    ranking.sort(key=lambda x: x[1], reverse=True)
    
    # Return a list of IP blocks ranked by preference (higher score first)
    return [ip for ip, score in ranking]


#---------------------------END-------------------------------------------------------



#--------------------IP BLOCK PREFERENCES DETERMINATION-------------------------------

def rank_as_for_ip_blocks(ip_cidr, autonomousSystems):
    # Convert the IP block CIDR to a network object, correcting for host bits if necessary
    ip_network = ipaddress.ip_network(ip_cidr, strict=False)
    
    # Create a list of tuples (AS ID, total score)
    ranking = []
    for as_id, as_cidr in autonomousSystems.items():
        # Convert the AS CIDR to a network object
        as_network = ipaddress.ip_network(as_cidr, strict=False)
        
        # Calculate the aggregateability score based on CIDR prefix
        prefix_diff = abs(ip_network.prefixlen - as_network.prefixlen)
        aggregateability_score = 32 - prefix_diff  # Example for IPv4
        
        # Calculate network similarity score based on longest common prefix length
        lcpl = get_common_prefix_length(ip_network, as_network)
        
        # Summing up scores: prioritize AS's with higher LCPL and similar prefix length
        total_score = (lcpl * 2) + aggregateability_score  # Weight LCPL more
        
        ranking.append((as_id, total_score))
    
    # Sort the list of tuples by the second item (total score), descending order
    ranking.sort(key=lambda x: x[1], reverse=True)
    
    # Return a list of AS's ranked by preference (higher score first)
    return [as_id for as_id, score in ranking]

#--------------------END--------------------------------------------------------------



#----------------------------RANDOM MATCHING GENERATION (to showcase difference in results) -------------------------

# Function to perform random matchings
def random_match_and_count_aggregations(autonomousSystems, ipBlocks):
    # Create lists of AS IDs and IP blocks
    as_ids = list(autonomousSystems.keys())
    ips = ipBlocks.copy()
    
    # Shuffle the IP blocks to ensure randomness
    random.shuffle(ips)
    
    # Match AS IDs to IP blocks directly after shuffling
    random_matchings = dict(zip(as_ids, ips))
    
    # Count aggregateable pairs
    aggregations = 0
    for as_id, ip in random_matchings.items():
        as_cidr = autonomousSystems[as_id]
        if can_aggregate(as_cidr, ip):
            aggregations += 1
            
    return random_matchings, aggregations


#-----------------------------------------END----------------------------------------------------------------



#-------------------- PROCESS VIEWING----------------------------------------

# print("Autonomous Systems:")
# for as_id, as_block in autonomousSystems.items():
#     print(f"{as_id}: {as_block}")
# print("\nIP Blocks:")
# for block in ipBlocks:
#     print(block)


# for as_id, as_block in autonomousSystems.items():
#     preference_list = rank_ip_blocks_for_as(as_block, ipBlocks)
#     print(f"Preference list for {as_id} based on block {as_block}:")
#     print(preference_list)
#     print(can_aggregate(as_block, preference_list[0]))
#     if(can_aggregate(as_block, preference_list[0]) == True):
#         aggregations+=1
#     print()

# for ip_block in ipBlocks:
#     preference_list = rank_as_for_ip_blocks(ip_block, autonomousSystems)
#     print(f"Preference list for IP block {ip_block} based on AS's:")
#     print(preference_list)
#     print()
# print(aggregations)

#-----------------------------------END ----------------------------------


# Gale-Shapley algorithm
def gale_shapley(as_prefs, ip_prefs):
    # Everyone is free initially
    free_as = list(as_prefs.keys())
    engagements = {}
    proposals = {ip: None for ip in ip_prefs}

    while free_as:
        as_id = free_as.pop(0)
        for ip in as_prefs[as_id]:
            if proposals[ip] is None:
                proposals[ip] = as_id
                engagements[as_id] = ip
                break
            else:
                current_as = proposals[ip]
                if ip_prefs[ip].index(as_id) < ip_prefs[ip].index(current_as):
                    free_as.append(current_as)
                    proposals[ip] = as_id
                    engagements[as_id] = ip
                    if current_as in engagements:
                        del engagements[current_as]
                    break
    return engagements


aggregationsSMP = 0
aggregationsRAND = 0

for i in range(10):
    autonomousSystems, ipBlocks = generate_as_ip_blocks(10, 10)

    as_prefs = {as_id: rank_ip_blocks_for_as(as_block, ipBlocks) for as_id, as_block in autonomousSystems.items()}
    ip_prefs = {ip: rank_as_for_ip_blocks(ip, autonomousSystems) for ip in ipBlocks}

    matchings = gale_shapley(as_prefs, ip_prefs)
    # print("Matchings:")
    # for as_id, ip in matchings.items():
    #     print(f"{as_id} is matched with {ip}")

    total_aggregations = count_aggregations(matchings, autonomousSystems)
    print("Total number of possible aggregations between the pairs:", total_aggregations)
    aggregationsSMP+= total_aggregations

    random_matchings, total_aggregations = random_match_and_count_aggregations(autonomousSystems, ipBlocks)
    print("Total number of possible aggregations between the pairs IF RANDOM:", total_aggregations)
    aggregationsRAND+=total_aggregations

print(str(aggregationsSMP) + " SMP Aggs")
print(str(aggregationsRAND) + " RAND Aggs")

