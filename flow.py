import os, subprocess, re, matplotlib, time, numpy
matplotlib.use('Agg')
import matplotlib.pyplot as plt

iter = 5
ind = numpy.arange(5)
width = 0.70       # the width of the bars
fig, ax = plt.subplots(figsize=(10,7))

ax.set_xticks(ind+width)
ax.set_ylabel('No of hash buckets')
ax.set_xlabel('Depth of the bucket')
ax.set_xticklabels( ('0', '1', '2', '3', '4') )


def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.text(rect.get_x()+rect.get_width()/2., 1.05*height, '%d'%int(height),
                ha='center', va='bottom')

# Get flow table size
pattern = 'Flow Table limit.*\s(\d+)'
output = subprocess.check_output('vrouter --info', shell=True, stderr=subprocess.STDOUT)
tablesize = re.search(pattern, output, re.M).group(1)
keys = int(tablesize)/4
okeys = 2048

def get_flow_counts():
    os.system('fab -H ubuntu@169.254.0.3 -p ubuntu --no-pty -- sudo nohup /var/tmp/client.sh >> test.log &')
    time.sleep(10)
    pattern = '^\s*(\d+).*1.1.1.'
    old_indices = 0
    flow = dict()
    oflow = dict()
    while True:
        # Get the indices
        output = subprocess.check_output('flow -l', shell=True, stderr=subprocess.STDOUT)
        indices = re.findall(pattern, output, re.M)
        if len(indices) <= old_indices:
            break
        old_indices = len(indices)
        time.sleep(30)

    # Create dict
    for i in range(keys):
        flow[i] = 0
    for i in range(okeys):
        oflow[i] = 0

    for index in indices:
        key = int(index)/4
        if key >= keys:
            key = key - keys
            oflow[key] += 1
        else:
            flow[key] += 1
    return (flow.values(), oflow.values())

for i in range(iter):
    (flows, oflows) = get_flow_counts()
    values = (flows.count(0), flows.count(1), flows.count(2), flows.count(3), flows.count(4))
    ovalues = (oflows.count(0), oflows.count(1), oflows.count(2), oflows.count(3), oflows.count(4))
    print 'No of buckets with', '\n\t\t0 entry:', values[0], '\n\t\t1 entry:', values[1], '\n\t\t2 entry:', values[2], '\n\t\t3 entry:', values[3], '\n\t\t4 entry:', values[4]
    print 'No of overflow buckets with', '\n\t\t0 entry:', ovalues[0], '\n\t\t1 entry:', ovalues[1], '\n\t\t2 entry:', ovalues[2], '\n\t\t3 entry:', ovalues[3], '\n\t\t4 entry:', ovalues[4]
    rects = ax.bar(ind+width, values, width, alpha=0.5, align='center')
    autolabel(rects)
    time.sleep(240)

plt.savefig('/var/www/html/test')

