#!/usr/bin/env python3
import subprocess,json,time,datetime,csv,os,argparse,tempfile
from statistics import mean
from urllib.parse import urlparse
from collections import defaultdict
class Colors:
    GREEN='\033[92m';RESET='\033[0m';BOLD='\033[1m';CYAN='\033[96m';YELLOW='\033[93m';DIM='\033[2m'
BASE_URL="http://127.0.0.1:5000"
ENDPOINTS_TO_TEST=[
    {"name":"GET /usage","method":"GET","path":"/usage"},
    {"name":"GET /capabilities","method":"GET","path":"/capabilities"},
    {"name":"POST /pattern-check","method":"POST","path":"/pattern-check","headers":{"Content-Type":"application/json"},"body":{"data":"benign string"}},
    {"name":"POST /pattern-check-contract","method":"POST","path":"/pattern-check-contract","headers":{"Content-Type":"application/json"},"body":{"data":"benignstring"}},
    {"name":"GET /delay/200ms","method":"GET","path":"/delay/200"},
]
def measure_request(endpoint_config):
    full_url=f"{endpoint_config['base_url']}{endpoint_config['path']}";url_scheme=urlparse(full_url).scheme;curl_format=json.dumps({"status_code":"%{http_code}","dns_time_s":"%{time_namelookup}","tcp_time_s":"%{time_connect}","tls_time_s":"%{time_appconnect}","ttfb_s":"%{time_starttransfer}","total_time_s":"%{time_total}"})
    with tempfile.NamedTemporaryFile(mode='w+',delete=True,encoding='utf-8') as body_file:
        command=["curl","-s","-o",body_file.name,"-w",curl_format,full_url];command.extend(["-X",endpoint_config.get("method","GET")])
        for key,value in endpoint_config.get("headers",{}).items():command.extend(["-H",f"{key}: {value}"])
        if"body"in endpoint_config:command.extend(["-d",json.dumps(endpoint_config["body"])])
        try:
            result=subprocess.run(command,capture_output=True,text=True,check=True);body_file.seek(0);snippet=body_file.read(50).replace('\n',' ');raw_data_s=json.loads(result.stdout)
            timing_data_ms={"dns_time_ms":round(float(raw_data_s['dns_time_s'])*1000,3),"tcp_time_ms":round(float(raw_data_s['tcp_time_s'])*1000,3),"ttfb_ms":round(float(raw_data_s['ttfb_s'])*1000,3),"total_time_ms":round(float(raw_data_s['total_time_s'])*1000,3)}
            if url_scheme=='https':
                tls_time_ms=round(float(raw_data_s['tls_time_s'])*1000,3);timing_data_ms['tls_time_ms']=tls_time_ms;timing_data_ms['tls_handshake_ms']=round(tls_time_ms-timing_data_ms['tcp_time_ms'],3)
            else:
                timing_data_ms['tls_time_ms']='N/A';timing_data_ms['tls_handshake_ms']='N/A'
            return{"name":endpoint_config["name"],"timestamp":datetime.datetime.now().isoformat(),"status_code":raw_data_s['status_code'],"body_snippet":snippet,**timing_data_ms}
        except FileNotFoundError:print(f"{Colors.BOLD}ERROR: `curl` not found.{Colors.RESET}");exit(1)
        except(subprocess.CalledProcessError,json.JSONDecodeError)as e:return{"name":endpoint_config["name"],"timestamp":datetime.datetime.now().isoformat(),"status_code":"000","error":str(e),"body_snippet":""}
def draw_dashboard(results,terminal_width,current_test_info=""):
    GRAPH_HEIGHT=7;Y_AXIS_LABEL_WIDTH=10;LOG_HISTORY_COUNT=3;print('\033[2J\033[H',end='');print(f"{Colors.BOLD}{Colors.GREEN}--- API Performance Dashboard (UTC {datetime.datetime.utcnow().strftime('%H:%M:%S')}) ---{Colors.RESET}");print(f"{Colors.YELLOW}{current_test_info}{Colors.RESET}")
    if not results:return
    successful_results=[r for r in results if"error"not in r];avg_total=mean([r.get('total_time_ms',0)for r in successful_results])if successful_results else 0;print(f"Total Requests: {Colors.CYAN}{len(results):<5}{Colors.RESET} Overall Avg Total Time: {Colors.CYAN}{avg_total:7.3f}ms{Colors.RESET}\n")
    grouped_results=defaultdict(list);
    for res in results:grouped_results[res['name']].append(res)
    for endpoint_config in ENDPOINTS_TO_TEST:
        endpoint_name=endpoint_config['name'];endpoint_results=grouped_results.get(endpoint_name,[])
        if not endpoint_results:continue
        num_runs=len(endpoint_results);print(f"{Colors.BOLD}{endpoint_name}{Colors.RESET} {Colors.DIM}({num_runs} runs total){Colors.RESET}");graph_width=terminal_width-Y_AXIS_LABEL_WIDTH-3;latencies=[r.get('total_time_ms',0)for r in endpoint_results];plot_points=[]
        if num_runs>graph_width:
            bucket_size=num_runs/graph_width
            for i in range(graph_width):
                start_index=int(i*bucket_size);end_index=int((i+1)*bucket_size);bucket_slice=latencies[start_index:end_index]
                if bucket_slice:plot_points.append(mean(bucket_slice))
                else:plot_points.append(latencies[start_index])
        else:plot_points=latencies
        min_lat=min(latencies)if latencies else 0;max_lat=max(latencies)if latencies else 1;lat_range=max_lat-min_lat if max_lat > min_lat else 1;canvas=[[' 'for _ in range(len(plot_points))]for _ in range(GRAPH_HEIGHT)]
        for i,lat in enumerate(plot_points):
            y_pos=0 
            if lat_range > 0:y_pos=int(((lat-min_lat)/lat_range)*(GRAPH_HEIGHT-1))
            canvas[y_pos][i]=f"{Colors.GREEN}•{Colors.RESET}"
        for i in range(GRAPH_HEIGHT - 1,-1,-1):
            y_label_val=min_lat+(i/(GRAPH_HEIGHT-1))*lat_range;y_label=f"{y_label_val:{Y_AXIS_LABEL_WIDTH-3}.3f}ms";print(f"{Colors.CYAN}{y_label}{Colors.RESET} | {''.join(canvas[i])}")
        axis_line=" "*(Y_AXIS_LABEL_WIDTH+1)+"└"+"─"*len(plot_points);print(axis_line);label_start="1";label_mid=f"{num_runs//2}";label_end=f"{num_runs}";scale_labels=" "*(Y_AXIS_LABEL_WIDTH+1)
        if num_runs==1:scale_labels+=label_start
        elif num_runs>1:
            mid_pos=(len(plot_points)//2)-(len(label_mid)//2);end_pos=len(plot_points)-len(label_end);scale_labels+=label_start
            if mid_pos>len(label_start):scale_labels+=" "*(mid_pos-len(label_start))+label_mid
            if end_pos>mid_pos+len(label_mid):scale_labels+=" "*(end_pos-(mid_pos+len(label_mid)))+label_end
        print(scale_labels);print(f"{Colors.DIM}  Recent Queries:{Colors.RESET}")
        for res in endpoint_results[-LOG_HISTORY_COUNT:]:
            status=res.get('status_code','ERR');time_val=res.get('total_time_ms',0);status_color=Colors.GREEN if str(status).startswith('2')else Colors.YELLOW;print(f"  - {res.get('timestamp','')[11:23]} | Status: {status_color}{status}{Colors.RESET} | Total: {time_val:.3f}ms")
        print("")
def main():
    parser=argparse.ArgumentParser(description="API Performance Measurement Tool.");parser.add_argument("--base-url",default=BASE_URL,help="Base URL of the API to test.");parser.add_argument("--runs",type=int,default=50,help="Number of requests to make *per endpoint*.");parser.add_argument("--delay",type=int,default=100,help="Delay between requests in milliseconds.");args=parser.parse_args();timestamp=datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S");csv_filename=f"performance_results_{timestamp}.csv"
    csv_headers=["timestamp","name","status_code","body_snippet","dns_time_ms","tcp_time_ms","tls_time_ms","tls_handshake_ms","ttfb_ms","total_time_ms","error"]
    with open(csv_filename,"w",newline="",encoding='utf-8')as f:
        writer=csv.DictWriter(f,fieldnames=csv_headers);writer.writeheader();all_results=[];terminal_width=100
        try:terminal_width,_=os.get_terminal_size()
        except OSError:pass
        total_endpoints=len(ENDPOINTS_TO_TEST);print(f"{Colors.GREEN}Starting performance test... Saved to {Colors.BOLD}{csv_filename}{Colors.RESET}");time.sleep(2)
        try:
            for i,endpoint_config in enumerate(ENDPOINTS_TO_TEST):
                endpoint_config['base_url']=args.base_url
                for run_num in range(args.runs):
                    current_test_info=f"Testing '{endpoint_config['name']}' ({i+1}/{total_endpoints}), Run {run_num+1}/{args.runs}";result=measure_request(endpoint_config);all_results.append(result);writer.writerow({k:result.get(k,"")for k in csv_headers});draw_dashboard(all_results,terminal_width,current_test_info);time.sleep(args.delay/1000.0)
        except KeyboardInterrupt:print(f"\n\n{Colors.BOLD}Test interrupted.{Colors.RESET}")
        finally:print(f"\n{Colors.GREEN}Test finished. Results saved to {Colors.BOLD}{csv_filename}{Colors.RESET}")
if __name__=="__main__":
    main()
