from celery import shared_task , chain
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests , json , threading , os , signal , ctypes , base64
from urllib.parse import urlparse 
from django.db.models import Case, When, Value, IntegerField
from vulnerability_monitor.tasks import read_write_list
from programs_monitor.tasks import sendmessage
from vulnerability_monitor.tasks import *
from django.db import transaction
from infodisclosure_backend.settings import *

OUTPUT_PATH = 'url_monitor/outputs'

EXTS = ['js','mjs','jsx','ts','tsx']

def clear_labels(self):
    Url.objects.all().update(label="available")
    NewUrl.objects.all().update(label="available")
    UrlChanges.objects.all().update(label="available")
    SubdomainParameter.objects.all().update(label='available')
    Parameter.objects.all().update(label = 'available')


def run_fallparams(input : str , headers : list) -> list:
    try : 
        command = [
            "fallparams",
            "-u", input,
            "-X" , "POST",
            "-X", "GET",
            "-silent",
            "-duc",

        ]
        if headers:
            for h in headers:
                if h:
                    command.extend(["-H", h])

        result = subprocess.run(
            command,
            shell=False,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="ignore"

        )
        
        parameters = result.stdout.splitlines()
        return parameters
    
    except Exception as e:
        sendmessage(f"  [Url-Watcher] ❌ Error Fallparams {input} : {str(e)}", colour="RED" , telegram=True)
        return []



def generate_body_hash(url: str) -> str:
    try:
        response = requests.get(url, timeout=30, verify=True, headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
        "Cache-Control": "no-cache","Pragma": "no-cache"},
    )
        body_bytes = response.content 
        if len(body_bytes) < MAX_CONTENT_SIZE:
            return hashlib.sha256(body_bytes).hexdigest()
        else:
            return ''
    except Exception as e:
        return None


def generate_base64_content(url: str) -> str:
    try:
        response = requests.get(url, timeout=30, verify=True, headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
        "Cache-Control": "no-cache","Pragma": "no-cache"},
    )
        body_bytes = response.content
        if len(body_bytes) < MAX_CONTENT_SIZE:
            return base64.b64encode(body_bytes).decode("utf-8")
        else:
            return ''
    
    except Exception as e:
        return None



PR_SET_PDEATHSIG = 1

try:
    _libc = ctypes.CDLL("libc.so.6")
except OSError:
    _libc = None

def _preexec():
    def _inner():
        if _libc is not None:
            try:
                _libc.prctl(PR_SET_PDEATHSIG, signal.SIGTERM)
            except Exception:
                pass
        os.setsid()
    return _inner

def _killpg(p: subprocess.Popen):
    try:
        pgid = os.getpgid(p.pid)
        os.killpg(pgid, signal.SIGTERM)
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(pgid, signal.SIGKILL)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def run_command(cmd_list, on_line=None, timeout_ms=15*60*1000, idle_timeout_ms=120*1000, max_lines=None):
    p = None
    lines_seen = 0
    last_activity = time.monotonic()
    try:
        p = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            preexec_fn=_preexec
        )
        

        def _read_stderr(pipe):
            for line in iter(pipe.readline, ''):
                msg = line.strip()
                if msg:
                    sendmessage(f"[Url-Watcher] ⚠️ {msg}", colour="YELLOW" , telegram=True)
            pipe.close()

        def _read_stdout(pipe):
            nonlocal last_activity, lines_seen
            for line in iter(pipe.readline, ''):
                last_activity = time.monotonic()
                clean = line.strip()
                if clean:
                    lines_seen += 1
                    if on_line:
                        on_line(clean)
                    if max_lines and lines_seen >= max_lines:
                        break
            pipe.close()

        t_err = threading.Thread(target=_read_stderr, args=(p.stderr,), daemon=True)
        t_out = threading.Thread(target=_read_stdout, args=(p.stdout,), daemon=True)
        t_err.start(); t_out.start()

        deadline = time.monotonic() + (timeout_ms/1000.0) if timeout_ms else None

        while True:
            rc = p.poll()
            if rc is not None:
                break 
            now = time.monotonic()
            if deadline and now >= deadline:
                _killpg(p)
                sendmessage(f"[Url-Watcher] ⏱ Hard timeout: {' '.join(cmd_list)}", colour="RED" , telegram=True)
                break
            if idle_timeout_ms and (now - last_activity) >= (idle_timeout_ms/1000.0):
                _killpg(p)
                sendmessage(f"[Url-Watcher] ⏱ Idle timeout (no output): {' '.join(cmd_list)}", colour="RED" , telegram=True)
                break
            time.sleep(0.2)

        if t_out.is_alive(): t_out.join(timeout=1)
        if t_err.is_alive(): t_err.join(timeout=1)

    except Exception as e:
        if p:
            _killpg(p)
        sendmessage(f"[Url-Watcher] ❌ Failed: {' '.join(cmd_list)} - {e}", colour="RED" , telegram=True)



def run_waybackurls(subdomain: str, on_line):
    sendmessage(f"[Url-Watcher] ℹ️ Starting Waybackurls for '{subdomain}'...")
    run_command(["waybackurls", subdomain], on_line=on_line)


def run_katana(subdomain: str, on_line):
    sendmessage(f"[Url-Watcher] ℹ️ Starting Katana for '{subdomain}'...")
    run_command(["nice-katana", subdomain], on_line=on_line)



def run_ffuf(subdomain_obj, subdomain: str, isNewUrl , insert_url_func,  timeout: int):

    sendmessage(f"[Url-Watcher] ℹ️ Starting FFUF for '{subdomain}'...")
    
    def run_ffuf_command(target: str, wordlist: str, tag: str):

        output_path = f"{OUTPUT_PATH}/ffuf_out/ffuf_{tag}.json"

        command = [
            "ffuf",
            "-u", target,
            "-w", wordlist,
            "-H","User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:145.0) Gecko/20100101 Firefox/145.0",
            "-ac",
            "-of", "json",
            "-mc", "200-299,301,302,307,401,403,404,405,500", # filter 403
            "-o", output_path,
            "-recursion",
            "-recursion-depth", "5",
            # "-t", "40",
            # "-p", "0.05-0.15",
            "-s"
        ]

        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            process.communicate(timeout=timeout)

            # ---- PARSE JSON HERE ----
            if os.path.exists(output_path):
                data = json.load(open(output_path))
                return data.get("results", [])
            else:
                return []

        except subprocess.TimeoutExpired:
            process.kill()
            sendmessage(f"[Url-Watcher] ⛔ FFUF timed out after {timeout}s")
            return []

        except Exception as e:
            sendmessage(f"[Url-Watcher] ❌ Error running FFUF: {e}")
            return []



    patterns = [
        (f"{subdomain}/FUZZ", f"{WORDLIST_PATH}/raft-large-directories.txt",          "slash"),
        # (f"{subdomain}FUZZ",  f"{WORDLIST_PATH}/swagger-wordlist.txt",                "noslash"),
        # (f"{subdomain}/FUZZ.html", f"{WORDLIST_PATH}/raft-large-words-lowercase.txt", "html"),
        # (f"{subdomain}/FUZZ.aspx", f"{WORDLIST_PATH}/raft-large-words-lowercase.txt", "aspx"),
        # (f"{subdomain}/FUZZ", f"{WORDLIST_PATH}/raft-large-words-lowercase.txt",      "backup"),
    ]

    try : 
        for target, wordlist, tag in patterns:
            results = run_ffuf_command(target, wordlist, tag)
            for r in results:
                if "url" in r:
                    insert_url_func(
                        subdomain_obj,
                        r["url"],
                        isNewUrl,
                        "ffuf"
                    )
        

    except Exception as e:
        sendmessage(f"[Url-Watcher] ❌ Error: {e}")
        return None



def discover_urls(self, label):

    def insert_url(subdomain_obj, url, isNewUrl , tool):
        clean_url = urlparse(url)
        matched_ext = "none"
        for ext in EXTENSION:
            if clean_url.path.endswith(ext[1]):
                matched_ext = ext[0]
                break

        if matched_ext in EXTS:
            new_body_hash = generate_body_hash(url)
            new_base64_content = generate_base64_content(url)

        else:
            new_body_hash = ""
            new_base64_content = ""

        try:
            resp = requests.get(url, timeout=60)
            status = resp.status_code
        except requests.RequestException:
            status = None

        obj, created = Url.objects.get_or_create(
            subdomain=subdomain_obj.discovered_subdomain,
            path=clean_url.path.strip().rstrip("/") or "/",
            defaults={
                "tool": tool,
                "query": clean_url.query,
                "ext": matched_ext,
                "url": url,
                "base64_content" : new_base64_content,
                "body_hash": new_body_hash,
                "status": status,
            },
        )

        if created:
            obj.label = "new"
            obj.save()


        if isNewUrl and subdomain_obj.label == "available": 
            obj2, created2 = NewUrl.objects.get_or_create(
                subdomain=subdomain_obj.discovered_subdomain,
                path=clean_url.path,
                diff_type="url",
                defaults={
                    "tool": tool,
                   "query": clean_url.query,
                   "ext": matched_ext,
                   "base64_content": new_base64_content,
                   "url": url,
                   "body_hash": new_body_hash,
                    "status": status,
                },
             )

            if created2:
                obj2.label = "new"
                obj2.save()


            if matched_ext in EXTS:

                obj3, created3 = NewUrl.objects.get_or_create(
                    subdomain=subdomain_obj.discovered_subdomain,
                    body_hash=new_body_hash,
                    diff_type="hash",
                    defaults={
                       "tool": tool,
                       "query": clean_url.query,
                       "ext": matched_ext,
                       "path": clean_url.path,
                       "base64_content": new_base64_content,
                       "url": url,
                       "body_hash": new_body_hash,
                        "status": status,
                   },
                )

                if created3:
                    obj3.label = "new"
                    obj3.save()


    sendmessage(f"[Url-Watcher] ℹ️ Starting Url Discovery Assets (label : {label})", colour="CYAN" , telegram=True)

    if label == 'new' : 
        subdomains = SubdomainHttpx.objects.filter(label=label)
    else : 
        subdomains = SubdomainHttpx.objects.filter(label=label, discovered_subdomain__wildcard__tools__tool_name="daily_narrow_monitoring")

    for subdomain in subdomains:
        if subdomain.label == "new":
            run_katana(
                subdomain.httpx_result,
                on_line=lambda url, sub=subdomain: insert_url(sub, url , False , 'katana')
            )
            run_waybackurls(
               subdomain.httpx_result,
               on_line=lambda url, sub=subdomain: insert_url(sub, url , False, 'waybackurls')
            )
            run_ffuf(
                subdomain, subdomain.httpx_result , False , insert_url , 900
            )

        elif subdomain.label == "available":
            run_katana(
                subdomain.httpx_result,
                on_line=lambda url, sub=subdomain: insert_url(sub, url , True, 'katana')
            )
            
            run_ffuf(
                subdomain, subdomain.httpx_result , True , insert_url , 900
            )

    sendmessage(f"[Urls-Watcher] ✅ URLs Discovery Successfully Done" , colour="CYAN" , telegram=True)




def detect_urls_changes(self):
    sendmessage(
        "[Urls-Watcher] ℹ️ Starting Detect URLs Changes (Body-Hash , Query-Changes , Status-Changes)",
        colour="CYAN",
        telegram=True
    )

    urls = list(Url.objects.filter(
        label='available',
        subdomain__wildcard__tools__tool_name="daily_narrow_monitoring"
    ))

    for i in range(0, len(urls), BATCH_SIZE):
        batch = urls[i:i+BATCH_SIZE]
        url_changes_to_create = []
        urls_to_update = []

        for url in batch:
            
            changes = {}

            try:
                
                response = requests.get(
                    url.url,
                    timeout=30,
                    verify=True,
                    headers={
                        "Cache-Control": "no-cache",
                        "Pragma": "no-cache",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36"
                    },
                )
                body_bytes = response.content
                if len(body_bytes) < MAX_CONTENT_SIZE:
                    new_body_hash = hashlib.sha256(body_bytes).hexdigest()
                    new_base64_content = base64.b64encode(body_bytes).decode("utf-8")
                else:
                    new_body_hash = ''
                    new_base64_content = ''

                new_status = str(response.status_code)
                new_query = url.query

            except requests.RequestException:
                continue

            if url.body_hash != new_body_hash:
                changes['body_hash_change'] = f"{url.body_hash} -> {new_body_hash}"
                url.body_hash = new_body_hash

            if url.base64_content != new_base64_content:
                changes['base64_change'] = f"{url.base64_content} -> {new_base64_content}"
                url.base64_content = new_base64_content

            if url.status != new_status:
                changes['status_change'] = f"{url.status} -> {new_status}"
                url.status = new_status

            if url.query != new_query:
                changes['query_change'] = f"{url.query} -> {new_query}"
                url.query = new_query

            if changes:
                url.label = 'new'
                urls_to_update.append(url)
                url_changes_to_create.append(
                    UrlChanges(
                        url=url,
                        query_change=changes.get('query_change', ''),
                        base64_content_change=changes.get('base64_change', ''),
                        body_hash_change=changes.get('body_hash_change', ''),
                        status_change=changes.get('status_change', ''),
                        label="new",
                        ext=url.ext
                    )
                )

            time.sleep(REQUEST_DELAY)

        if url_changes_to_create:
            UrlChanges.objects.bulk_create(url_changes_to_create)
        if urls_to_update:
            Url.objects.bulk_update(
                urls_to_update,
                ['body_hash', 'base64_content', 'status', 'query', 'label']
            )

    sendmessage(
        "[Urls-Watcher] ✅ Detect URLs Changes Successfully Done",
        colour="CYAN",
        telegram=True
    )



def discover_parameter(self , label):
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Discover Parameters on Assets (label: {label})" , colour="CYAN")
    
    def parameters_insert_database(subdomain, parameters):
        for parameter in parameters:
            clean_parameter = parameter.replace('\x00', '')
	        
            if not clean_parameter.strip():
                continue

            obj, created = SubdomainParameter.objects.get_or_create(
                subdomain=subdomain,
                parameter=clean_parameter
            )
            if created:
                obj.label = "new"
                obj.save()
    

    if label == 'new' : 
        subdomains = SubdomainHttpx.objects.filter(label=label)
    else : 
        subdomains = SubdomainHttpx.objects.filter(label=label, discovered_subdomain__wildcard__tools__tool_name="daily_narrow_monitoring")
    
    for subdomain in subdomains :
        sendmessage(f"[Url-Watcher] ℹ️ Starting Parameter Discovery for '{subdomain}'...")
        headers = list(RequestHeaders.objects.filter(asset_watcher=subdomain.discovered_subdomain).values_list('header', flat=True))
        read_write_list(list(subdomain.discovered_subdomain.url_set.values_list('url', flat=True)) , f"{OUTPUT_PATH}/urls.txt" , 'w')
        parameters = run_fallparams(f"{OUTPUT_PATH}/urls.txt" , headers)
        parameters_insert_database (subdomain.discovered_subdomain , parameters)

    sendmessage(f"[Urls-Watcher] ✅ Parameter Discovery Successfully Done" , colour="CYAN")



def fuzz_parameters_on_urls(self , label):

    def save_x8_output_from_file(url_instance , json_file_path, url):
        try:
            with open(json_file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for item in data:
                method = item.get("method")
                injection_place = item.get("injection_place")
                for param in item.get("found_params", []):
                    obj, created = Parameter.objects.get_or_create(
                        url=url_instance,
                        method=method,
                        parameter=param.get("name"),
                        defaults={
                            "status": str(param.get("status")),
                            "reason_kind": param.get("reason_kind"),
                            "injection_place": injection_place
                        }
                    )
                    if created:
                        obj.label = 'new'
                        obj.save()

        except json.JSONDecodeError as e:
            sendmessage(f"[Url-Watcher] ❌ Failed to decode JSON for {url_instance}: {str(e)}", colour="RED",telegram=True)
        except FileNotFoundError:
            sendmessage(f"[Url-Watcher] ❌ JSON file not found: {json_file_path}", colour="RED",telegram=True)
        except Exception as e:
            sendmessage(f"[Url-Watcher] ❌ Failed to save parameters for {url_instance}: {str(e)}", colour="RED" , telegram=True)

    def run_x8(url_instance , url, parameters_path, headers):
        for method in ["GET", "POST"]:
            output_file = f"{OUTPUT_PATH}/x8_output_{method}.json"
            command = [
                "x8",
                "-u", url,
                "-w", parameters_path,
                "--output-format", "json",
                "-o", output_file,
                "-X", method,
                '-d', '100',
                '-L'
            ]

            if headers:
                valid_headers = [h.strip() for h in headers if h and ":" in h]
                for h in valid_headers:
                    command.extend(["-H", h])

            try:
                process = subprocess.Popen(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                try:
                    stdout, stderr = process.communicate(timeout=1000)
                except subprocess.TimeoutExpired:
                    process.kill()
                    stdout, stderr = process.communicate()
                    sendmessage(f"[Url-Watcher] ⏱ Timeout X8 {url} with {method}", colour="RED" , telegram=True)
                    continue 

                if process.returncode != 0:
                    sendmessage(f"[Url-Watcher] ❌ X8 failed on {url} with {method}: {stderr.strip()}", colour="RED" , telegram=True)
                    continue

                save_x8_output_from_file(url_instance , output_file, url)

            except Exception as e:
                sendmessage(f"[Url-Watcher] ❌ Unexpected error X8 {url} with {method}: {str(e)}", colour="RED" , telegram=True)

    sendmessage(f"[Urls-Watcher] ℹ️ Starting Fuzz Parameters on URLs (label: {label})", colour="CYAN" , telegram=True)


    if label == 'new' : 
        subdomains = SubdomainHttpx.objects.filter(label=label)
    else : 
        subdomains = SubdomainHttpx.objects.filter(label=label, discovered_subdomain__wildcard__tools__tool_name="daily_narrow_monitoring")


    for subdomain in subdomains:
        parameters = subdomain.discovered_subdomain.subdomainparameter_set.values_list('parameter', flat=True)
        read_write_list(list(parameters), f"{WORDLIST_PATH}/raft-large-words-lowercase.txt", 'a')

        sendmessage(f"[Urls-Watcher] ℹ️ Starting Fuzz Parameters on {subdomain} URLs" , colour="CYAN")
        headers = list(RequestHeaders.objects.filter(asset_watcher=subdomain.discovered_subdomain).values_list('header', flat=True))
        urls = Url.objects.filter(subdomain=subdomain.discovered_subdomain).order_by(
            Case(
                When(label="new", then=Value(0)),
                default=Value(1),
                output_field=IntegerField()
            ),
        )
        for url in urls:
            if url.status != "403":
                run_x8(url, url.url, f"{WORDLIST_PATH}/raft-large-words-lowercase.txt", headers)

    sendmessage(f"[Urls-Watcher] ✅ Fuzzing Parameters on URLs Successfully Done" , colour="CYAN", telegram=True)



@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*29, time_limit=60*60*30)
def discover_urls_task(self, label):
    return discover_urls(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*29, time_limit=60*60*30)
def discover_parameter_task(self, label):
    return discover_parameter(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*29, time_limit=60*60*30)
def fuzz_parameters_on_urls_task(self, label):
    return fuzz_parameters_on_urls(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*29, time_limit=60*60*30)
def vulnerability_monitor_task(self, label):
    return vulnerability_monitor(label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*29, time_limit=60*60*30)
def detect_urls_changes_task(self):
    return detect_urls_changes(self)



@shared_task
def notify_done():
    sendmessage("[Urls-Watcher] ✅ URL Monitoring Successfully Done", colour="CYAN" , telegram=True)



@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    clear_labels(self)
    sendmessage("[Url-Watcher] ⚠️ Vulnerability Discovery Will be Started Please add Valid Headers ⚠️" , telegram=True)

    workflow = chain(
        discover_urls_task.s('new'),
        discover_parameter_task.si('new'),
        # fuzz_parameters_on_urls_task.si('new'), # Recommand to do not use it !
        vulnerability_monitor_task.si('new'),

        discover_urls_task.si('available'),
        discover_parameter_task.si('available'),
        # fuzz_parameters_on_urls_task.si('available'), # Recommand to do not use it !
        # vulnerability_monitor_task.si('available'), STUPID Work
        
        detect_urls_changes_task.si(),
        notify_done.si()
    )
    workflow.apply_async()
