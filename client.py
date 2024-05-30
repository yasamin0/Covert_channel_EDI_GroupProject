import socket
import struct
import argparse
import random
import time

def get_tweet():
    tweets = [
        "Exploring the world one step at a time. #Travel",
        "Just finished a great book! Any recommendations for what I should read next? #BookLovers",
        "The best way to predict the future is to create it. #Motivation",
        "Coffee is my best friend on this Monday morning. #MondayMotivation",
        "Just saw the most beautiful sunset. #Nature",
        "Working out: because it's good for the body, and the mind. #Fitness",
        "Nothing beats a home cooked meal. #Foodie",
        "Just watched the latest episode. No spoilers, but it was amazing! #TVShows",
        "There's nothing like a walk in the park to clear your mind. #Mindfulness",
        "Coding is not just a skill, it's a mindset. #Coding",
        "Just had the best cup of coffee. #CoffeeLovers",
        "The best part of my day is spending time with my family. #Family",
        "Just finished a 5k run. Feeling accomplished! #Running",
        "There's nothing like a good book to transport you to another world. #Reading",
        "Just baked the most delicious cookies. #Baking",
        "Music is the soundtrack of life. #Music",
        "There's nothing like the smell of fresh bread in the morning. #Baking",
        "Just finished a challenging workout. Feeling strong! #Fitness",
        "The best part of traveling is experiencing new cultures. #Travel",
        "Just finished a great podcast episode. Any recommendations for what I should listen to next? #Podcasts",
        "There's nothing like a good laugh to brighten your day. #Humor",
        "Just finished a DIY project. Feeling accomplished! #DIY",
        "The best part of my day is my morning yoga routine. #Yoga",
        "Just had the most delicious brunch. #Foodie",
        "There's nothing like a good movie to escape reality for a bit. #Movies",
        "Just finished a great book! Can't wait to start the next one. #Reading",
        "The best part of my day is my morning run. #Running",
        "Just had the most delicious pizza. #Foodie",
        "There's nothing like a good song to lift your spirits. #Music",
        "Just finished a challenging puzzle. Feeling accomplished! #Puzzles",
        "The best part of my day is my evening meditation. #Meditation",
        "Just had the most delicious ice cream. #Foodie",
        "There's nothing like a good book to relax before bed. #Reading",
        "Just finished a great movie! Can't wait to watch the sequel. #Movies",
        "The best part of my day is my afternoon walk. #Walking",
        "Just had the most delicious sushi. #Foodie",
        "There's nothing like a good podcast to learn something new. #Podcasts",
        "Just finished a great TV show! Can't wait for the next season. #TVShows",
        "The best part of my day is my evening tea. #Tea",
        "Just had the most delicious burger. #Foodie",
        "There's nothing like a good workout to start your day. #Fitness",
        "Just finished a great documentary! Learned so much. #Documentaries",
        "The best part of my day is my morning coffee. #Coffee",
        "Just had the most delicious salad. #Foodie",
        "There's nothing like a good game to have fun with friends. #Gaming",
        "Just finished a great album! Can't wait to listen to it again. #Music",
        "The best part of my day is my lunch break. #Lunch",
        "Just had the most delicious pasta. #Foodie",
        "There's nothing like a good book to start your day. #Reading",
        "Just finished a great video game! Can't wait to play the sequel. #Gaming",
        "The best part of my day is my evening read. #Reading"
    ]
    return random.choice(tweets)

def char_to_tos(char):
    return ord(char)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + (msg[i + 1] if i + 1 < len(msg) else 0)
        s = (s + w) & 0xffff
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return ~s & 0xffff

def construct_ip_header(src_ip, dst_ip, tos):
    version = 4
    ihl = 5
    tot_len = 20 + 20  # IP header + TCP header
    id = 54321
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)

    ihl_version = (version << 4) + ihl

    ip_header = struct.pack(
        '!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr
    )

    check = checksum(ip_header)
    ip_header = struct.pack(
        '!BBHHHBBH4s4s', ihl_version, tos, tot_len, id, frag_off, ttl, protocol, socket.htons(check), saddr, daddr
    )

    return ip_header

def construct_tcp_header(src_ip, dst_ip, src_port, dst_port):
    seq = 0
    ack_seq = 0
    doff = 5
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH', src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # Pseudo header fields
    src_addr = socket.inet_aton(src_ip)
    dest_addr = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = struct.pack('!4s4sBBH', src_addr, dest_addr, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_check = checksum(psh)
    tcp_header = struct.pack('!HHLLBBH', src_port, dst_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_check) + struct.pack('!H', urg_ptr)

    return tcp_header

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send raw TCP packets.")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_port", type=int, help="Source port")
    parser.add_argument("dst_port", type=int, help="Destination port")
    parser.add_argument("secret_message", help="Secret message to send")

    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as s:
        for char in args.secret_message:
            tos_value = char_to_tos(char)
            ip_header = construct_ip_header(args.src_ip, args.dst_ip, tos_value)
            tcp_header = construct_tcp_header(args.src_ip, args.dst_ip, args.src_port, args.dst_port)
            packet = ip_header + tcp_header
            s.sendto(packet, (args.dst_ip, 0))
            print(f"Sent packet with ToS value: {tos_value}")
            time.sleep(1)  # Wait a bit before sending the next packet

            # Send the tweet using standard TCP communication to ensure continuous flow
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
                tcp_sock.connect((args.dst_ip, args.dst_port))
                tweet = get_tweet()
                tcp_sock.sendall(tweet.encode())
                response = tcp_sock.recv(1024)
                print(f"Sent tweet: {tweet}")
                print(f"Received: {response.decode()}")
