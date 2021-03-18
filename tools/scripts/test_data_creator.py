# Copyright (c) Microsoft Corporation. All rights reserved.
#  Licensed under the MIT license.

import argparse
import random
import string

ap = argparse.ArgumentParser()
ap.add_argument("sender_size", help="The size of the sender's set", type=int)
ap.add_argument("receiver_size", help="The size of the receiver's set", type=int)
ap.add_argument("intersection_size", help="The desired size of the intersection", type=int)
ap.add_argument("-l", "--label_byte_count", help="The number of bytes used for the labels", type=int, default=0)
ap.add_argument("-i", "--item_byte_count", help="The number of bytes used for the items", type=int, default=64)
args = ap.parse_args()

sender_sz = args.sender_size
recv_sz = args.receiver_size
int_sz = args.intersection_size
label_bc = args.label_byte_count
item_bc = args.item_byte_count

sender_set = {}
letters = string.ascii_lowercase + string.ascii_uppercase
while len(sender_set) < sender_sz:
    item = ''.join(random.choice(letters) for i in range(item_bc))
    label = ''.join(random.choice(letters) for i in range(label_bc))
    sender_set[item] = label

recv_set = set()
while len(recv_set) < min(int_sz, recv_sz):
    item = random.choice(list(sender_set.keys()))
    recv_set.add(item)

while len(recv_set) < recv_sz:
    item = ''.join(random.choice(letters) for i in range(item_bc))
    if item not in sender_set:
        recv_set.add(item)

with open("db.csv", "w") as sender_file:
    for item, label in sender_set.items():
        sender_file.write(item + ((", " + label) if label_bc != 0 else '') + '\n')

with open("query.csv", "w") as recv_file:
    for item in recv_set:
        recv_file.write(item + '\n')
