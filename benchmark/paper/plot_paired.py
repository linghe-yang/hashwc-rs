"""Plot paired runs; retain censored observations as such."""
from pathlib import Path
import csv
import sys
from statistics import mean
from measurements import table
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

COLORS={'whcc':'#087e80','warmup':'#c77322','hashrand':'#66539c'}
LABEL={'whcc':'WHCC','warmup':'Warm-up','hashrand':'HashRand + virtual shares'}

def plot(folder, output=None):
    output = folder if output is None else output
    output.mkdir(exist_ok=True, parents=True)
    with (folder/'measurements.csv').open() as stream:
        rows=list(csv.DictReader(stream))
    summary=[]
    for family,protocol,n in sorted({(r['family'],r['protocol'],int(r['n'])) for r in rows}):
        group=[r for r in rows if (r['family'],r['protocol'],int(r['n']))==(family,protocol,n)]
        success=[r for r in group if r['status']=='success']
        row=dict(family=family,protocol=protocol,n=n,completed=len(success),
                 online_timeouts=sum(r['status']=='online_timeout' for r in group),
                 skipped=sum(r['status']=='not_run_after_two_timeouts' for r in group))
        if len(success)==2:
            for k in ('latency_ms','mean_cpu_ms','peak_party_rss_kib','sent_bytes','path_bytes','shared_bytes'):
                if all(r.get(k) for r in success):
                    row[k]=mean(float(r[k]) for r in success)
        summary.append(row)
    table(output/'paired-summary.csv',summary)
    for family,protocols in [('sui',['hashrand','whcc']),('aptos',['warmup','whcc'])]:
        data=[r for r in rows if r['family']==family]
        if not data:continue
        sizes=sorted({int(r['n']) for r in data})
        fig,axes=plt.subplots(1,3,figsize=(12,3.5),layout='constrained')
        for ax,(metric,title,scale) in zip(axes,[('sent_bytes','Mean sent / party (MiB)',2**20),
                ('mean_cpu_ms','Mean CPU / party (s)',1000),('latency_ms','Last party output (s)',1000)]):
            stacked=family=='aptos' and metric=='sent_bytes'
            for j,proto in enumerate(protocols):
                means=[]
                for i,n in enumerate(sizes):
                    group=[r for r in data if r['protocol']==proto and int(r['n'])==n]
                    good=[r for r in group if r['status']=='success']
                    values=[float(r[metric])/scale/(n if metric=='sent_bytes' else 1) for r in good]
                    x=i+(j-.5)*(.35 if stacked else .09)
                    if any(r['status']=='online_timeout' for r in group) and metric=='latency_ms':
                        ax.scatter(x,180,marker='^',color=COLORS[proto])
                        ax.annotate(f'{len(good)}/{len(group)}',(x,180),xytext=(0,5),textcoords='offset points')
                    # A partial pair has individual points, no two-run mean.
                    avg=mean(values) if len(values)==2 else float('nan')
                    means.append(avg)
                    if stacked and len(values)==2:
                        path=mean(float(r['path_bytes']) for r in good)/n/scale
                        ax.bar(x,path,.32,color=COLORS[proto],label=LABEL[proto] if i==0 else None)
                        ax.bar(x,avg-path,.32,bottom=path,color='#d3d7da',label='Shared control' if i==j==0 else None)
                        if proto=='whcc':
                            base=[float(r['sent_bytes'])/n/scale for r in data if r['protocol']=='warmup'
                                  and int(r['n'])==n and r['status']=='success']
                            if len(base)==2 and mean(base)>0:
                                saving=1-avg/mean(base)
                                ax.annotate(f'{saving:+.0%}',(i,max(avg,mean(base))),
                                            xytext=(0,4),textcoords='offset points',ha='center',fontsize=8)
                    ax.scatter([x+(k-.5)*.03 for k in range(len(values))],values,facecolors='none',
                               edgecolors=COLORS[proto] if not stacked else 'black',s=16,zorder=4)
                if not stacked:
                    ax.plot([i+(j-.5)*.09 for i in range(len(sizes))],means,color=COLORS[proto],label=LABEL[proto])
            ax.set(xticks=range(len(sizes)),xticklabels=sizes,xlabel='Parties',ylabel=title)
            if family=='sui' and metric!='sent_bytes':ax.set_yscale('log')
            else:ax.set_ylim(bottom=0)
            if stacked:ax.margins(y=.16)
            ax.grid(axis='y',alpha=.2)
        axes[0].legend(fontsize=8)
        for ext in ('png','pdf','svg'):
            fig.savefig(output/f'{family}-paired.{ext}',dpi=180)
        plt.close(fig)
if __name__=='__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    parser.add_argument('folder', type=Path, nargs='?', default=here/'results')
    parser.add_argument('--out', type=Path)
    args=parser.parse_args()
    plot(args.folder, args.out or (here/'figures' if args.folder == here/'results' else args.folder))

