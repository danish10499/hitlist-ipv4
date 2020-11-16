#!/usr/bin/env python

import argparse
import csv
import os 
import subprocess
import random
import pandas as pd
import calendar
import time
import datetime
import dateutil.relativedelta
from sampling import *

ONE_MILLION = 1000000
HUNDRED_THOUSAND = 100000
TEN_THOUSAND = 10000
THOUSAND_FIVE_HUNDRED = 1500


def driver(inputfile, protocol, characteristic, size, time, error, output, force):
    
    with open(inputfile, 'rb') as t:
        header_feat = t.readline().rstrip().decode("utf-8").split(',')
        try:
            pref_col_pos = str(header_feat.index('new_cidr')+1)
        except:
            pref_col_pos = 0
        try:
            asn_col_pos = str(header_feat.index('asn')+1)
        except:
            asn_col_pos = 0
        try:
            ver_col_pos = str(header_feat.index('protocol')+1) 
        except:
            ver_col_pos = 0
    
    if time != 0:
        present_time = datetime.datetime.fromtimestamp(int(time.time()))
        past_time = datetime.datetime.fromtimestamp(past)
        rd = dateutil.relativedelta.relativedelta (present_time,past_time)
        if rd.months > 2:
            print('A fresh scan is recommended to better capture the Internet behaviour but hitlist is still generated for the given input')
        
        
        
    if characteristic == 'cross_response':
        random_sampler(inputfile, THOUSAND_FIVE_HUNDRED, output)
        return
    
    if force == 'random' and size == 0:
        random_sampler(inputfile, HUNDRED_THOUSAND, output)
    elif force == 'random':
        random_sampler(inputfile, size, output)
        return
            
    if ver_col_pos == 0 and asn_col_pos == 0 and pref_col_pos == 0 and characteristic != 'cross_response':
        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require either Protocol Version or Prefix Length details') 
        return
    
    if protocol == 'TLS':
        if characteristic == 'all_version':
            if size == 0:
                if error == 1:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Protocol Version detail)')
                   
                elif error == 2:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Protocol Version details)')
                                             
                elif error >= 5:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    elif pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                    
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require either Protocol Version or Prefix Length details)')
                        
            else:
                if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)

                elif pref_col_pos != 0 and size <= TEN_THOUSAND:
                    subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                    stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require either Protocol Version or Prefix Length details) or mentioned size do not perform well')
##################                        
        elif characteristic == 'no_null_version':
            if size == 0:
                if error == 1:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Protocol Version detail)')
                   
                elif 2 <= error <= 5:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Protocol Version details)')
                                             
                elif error > 5:
                    if ver_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                    
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require either Protocol Version or Prefix Length details)')
                        
            else:
                if ver_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either elevant information to perform stratified sampling is missing (Require Protocol Version details) or mentioned size do not perform well')
##################                        
        elif characteristic == 'all_prefix-length':
            if size == 0:
                if error == 1:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', ONE_MILLION, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif 2 <= error <= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', HUNDRED_THOUSAND, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                                             
                elif error > 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', TEN_THOUSAND, output)
                        os.system('rm char_samp')
                    
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= HUNDRED_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', size, output)
                        os.system('rm char_samp')
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')            
##################                        
        elif characteristic == 'routable_prefix-length':
            if size == 0:
                if 1 <= error <= 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error >= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')  
##################                        
        elif characteristic == '24_prefix-length':
            if size == 0:
                if 1 <= error <= 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error >= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well') 
              
######################################################################################
    
    elif protocol == 'HTTP':
        if characteristic == 'all_prefix-length':
            if size == 0:
                if 1 <= error <= 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', ONE_MILLION, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error >= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', HUNDRED_THOUSAND, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= HUNDRED_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', size, output)
                        os.system('rm char_samp')
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')            
##################                        
        elif characteristic == 'routable_prefix-length':
            if size == 0:
                if error == 1:
                    if asn_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, asn_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
              
                    elif pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require ASN or Prefix Length detail)')
              
                elif 2 <= error <= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
                
                elif error > 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')  
##################                        
        elif characteristic == '24_prefix-length':
            if size == 0:
                if error == 1:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
              
                elif error == 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error > 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well') 
              
######################################################################################
    
    elif protocol == 'DNS':
        if characteristic == 'all_prefix-length':
            if size == 0:
                if 1 <= error <= 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', ONE_MILLION, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error >= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', HUNDRED_THOUSAND, output)
                        os.system('rm char_samp')
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= HUNDRED_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        cluster_sampler('char_sort.csv', 'char_cum.csv', 'char_samp', size, output)
                        os.system('rm char_samp')
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')            
##################                        
        elif characteristic == 'routable_prefix-length':
            if size == 0:
                if error == 1:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)

                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require ASN or Prefix Length detail)')
              
                elif 2 <= error <= 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
                
                elif error > 5:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well')  
##################                        
        elif characteristic == '24_prefix-length':
            if size == 0:
                if error == 1:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', ONE_MILLION, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
              
                elif error == 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', HUNDRED_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length detail)')
                   
                elif error > 2:
                    if pref_col_pos != 0:
                        subprocess.check_call(['./bash_input.sh', inputfile, pref_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', TEN_THOUSAND, output)
                        
                    else:
                        print('***ERROR*** Relevant information to perform stratified sampling is missing (Require Prefix Length details)')
                        
            else:
                if pref_col_pos != 0 and size >= TEN_THOUSAND:
                        subprocess.check_call(['./bash_input.sh', inputfile, ver_col_pos])
                        stratified_random_sampler('char_sort.csv', 'char_cum.csv', size, output)
                    
                else:
                    print('***ERROR*** Either relevant information to perform stratified sampling is missing (Require Prefix Length details) or mentioned size do not perform well') 
                    
    if force != 'random' or characteristic != 'cross_response':
        os.system('rm char_sort.csv char_cum.csv')
                    
                    
                    
    

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest='inputfile', required=True, help="Mention the source file that needs to be sampled")
    parser.add_argument("--p", dest='protocol', required=True, help="Mention the protocol of interest",
                        type=str,  choices=['TLS', 'HTTP', 'DNS'])
    parser.add_argument("--f", dest='force', help="Force random sample", 
                        type=str,  choices=['random']) 
    parser.add_argument("--c", dest='characteristic', help="Mention the characteristics that hitlist needs to express", default = 'null',
                        type=str,  choices=['all_version', 'no_null_version', 'all_prefix-length', 'routable_prefix-length', '24_prefix-length', 'cross_response'])
    parser.add_argument("--s", dest='size', help="Mention the desired sample size", default = 0,
                        type=int,  choices=[1500, 10000, 100000, 1000000])
    parser.add_argument("--e", dest='error', help="Mention the acceptable error", default = 5,
                        type=int,  choices=[1, 2, 5, 10])
    parser.add_argument("--out", dest='output', help="Directs the output to a name of your choice",
                        type=str, default = 'ipv4_hitlist_output.csv')
    parser.add_argument("--t", dest='time', help="Time of scan (Epoch time)",
                        type=int, default = 0)

    args = parser.parse_args()   
    
    if args.force != 'random' and args.characteristic == 'null':
        print('usage: hitlist.py [-h] --in INPUTFILE --p {TLS,HTTP,DNS} [--f {random}] --c')
        print('                  {all_version,no_null_version,all_prefix-length,routable_prefix-length,24_prefix-length,cross_response}')
        print('                  [--s {1500,10000,100000,1000000}] [--e {1,2,5,10}]')
        print('                  [--out OUTPUT] [--t TIME]')
        print('hitlist.py: error: the following arguments are required: --c')
        return


    driver(args.inputfile, args.protocol, args.characteristic, args.size, args.time, args.error, args.output, args.force)


if __name__ == '__main__':
    main()