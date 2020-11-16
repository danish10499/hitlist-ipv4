import random
import pandas as pd
import numpy as np
import csv


def random_sampler(filename, samp_size, out_file):
    sample = []
    with open(filename, 'rb') as f:
        linecount = sum(1 for line in f)
        f.seek(0)
        header_1 = f.readline().rstrip().decode("utf-8").split(',')
        random.seed()
        random_linenos = sorted(random.sample(range(linecount), samp_size), reverse = True)
        lineno = random_linenos.pop()
        for n, line in enumerate(f):
            if n == lineno:
                sample.append(line.rstrip().decode("utf-8").split(','))
                if len(random_linenos) > 0:
                    lineno = random_linenos.pop()
                else:
                    break
        df = pd.DataFrame(sample,columns=header_1)
        df = df.sort_values(by=['host']).reset_index(drop=True)
        df.to_csv(out_file, index=False)



def stratified_random_sampler(population_file, sample_file, samp_size, out_file):
    sample = []
    random_linenos = []
    with open(population_file, 'rb') as f, open(sample_file, 'rb') as s:
        linecount = sum(1 for line in f)
        samplecount = sum(1 for line in s)
        f.seek(0)
        header_1 = f.readline().rstrip().decode("utf-8").split(',')
        s.seek(0)
        header_2 = s.readline()
        i_row = s.readline().rstrip().decode("utf-8").split(',')
        i, count_lim = 0, 0

        while i < samplecount - 1:
            random.seed()
            size = round(((int(i_row[2])/linecount)*samp_size)+0.5)
            random_lines = random.sample(range(int(i_row[3])-int(i_row[2]),int(i_row[3])), size)
            i+=1
            count_lim+=size
            random_linenos.extend(random_lines)
            i_row = s.readline().rstrip().decode("utf-8").split(',')
            if count_lim >= samp_size:
                break
            
        random_linenos = sorted(random_linenos, reverse = True)
        lineno = random_linenos.pop()
            
        for n, line in enumerate(f):
            if n == lineno:
                sample.append(line.rstrip().decode("utf-8").split(','))
                if len(random_linenos) > 0:
                    lineno = random_linenos.pop()
                else:
                    break
        df = pd.DataFrame(sample,columns=header_1)
        df = df.sort_values(by=['host']).reset_index(drop=True)
        df = df.head(samp_size)
        df.to_csv(out_file, index=False)



def cluster_sampler(population_file, sample_file, cluster_input, samp_size, out_file):
    rang = pd.read_csv(sample_file, usecols= ['freq', 'cum'])
    np.random.seed()
    rang = rang.iloc[np.random.permutation(rang.index)].reset_index(drop=True)  
    rang.to_csv(cluster_input, index=False)
    sample = []
    random_linenos = []
    with open(population_file, 'rb') as f, open(cluster_input, 'rb') as s:
        linecount = sum(1 for line in f)
        samplecount = sum(1 for line in s)
        f.seek(0)
        header_1 = f.readline().rstrip().decode("utf-8").split(',')
        s.seek(0)
        header_2 = s.readline()
        i_row = s.readline().rstrip().decode("utf-8").split(',')
        i, count_lim = 0, 0

        while i < samplecount - 1:
            random.seed()
            size = round(((int(i_row[0])/linecount)*samp_size)+0.5)
            random_lines = random.sample(range(int(i_row[1])-int(i_row[0]),int(i_row[1])), size)
            i+=1
            count_lim+=size
            random_linenos.extend(random_lines)
            i_row = s.readline().rstrip().decode("utf-8").split(',')
            if count_lim >= samp_size:
                break
            
        random_linenos = sorted(random_linenos, reverse = True)
        lineno = random_linenos.pop()
            
        for n, line in enumerate(f):
            if n == lineno:
                sample.append(line.rstrip().decode("utf-8").split(','))
                if len(random_linenos) > 0:
                    lineno = random_linenos.pop()
                else:
                    break
        df = pd.DataFrame(sample,columns=header_1)
        df = df.sort_values(by=['host']).reset_index(drop=True)
        df = df.head(samp_size)
        df.to_csv(out_file, index=False)
