from celery import shared_task , chain
from .models import *
from asset_monitor.models import *
import subprocess , time , hashlib , requests , json , threading , os , signal , ctypes
from urllib.parse import urlparse 
from django.db.models import Case, When, Value, IntegerField
from vulnerability_monitor.tasks import read_write_list
from programs_monitor.tasks import sendmessage
from vulnerability_monitor.tasks import *


OUTPUT_PATH = 'url_monitor/outputs'

EXTS = ['js']

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
            "-X", "GET",
            "-X", "POST",
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
        sendmessage(f"  [Url-Watcher] ❌ Error Fallparams {input} : {str(e)}", colour="RED")
        return []



def generate_body_hash(url: str) -> str:
    try:
        response = requests.get(url, timeout=30, verify=True, headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.90 Safari/537.36",
        "Cache-Control": "no-cache","Pragma": "no-cache"},
    )
        body_bytes = response.content 
        return hashlib.sha256(body_bytes).hexdigest()
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
            preexec_fn=_preexec()
        )

        def _read_stderr(pipe):
            for line in iter(pipe.readline, ''):
                msg = line.strip()
                if msg:
                    sendmessage(f"[Url-Watcher] ⚠️ {msg}", colour="YELLOW")
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
                sendmessage(f"[Url-Watcher] ⏱ Hard timeout: {' '.join(cmd_list)}", colour="RED")
                break
            if idle_timeout_ms and (now - last_activity) >= (idle_timeout_ms/1000.0):
                _killpg(p)
                sendmessage(f"[Url-Watcher] ⏱ Idle timeout (no output): {' '.join(cmd_list)}", colour="RED")
                break
            time.sleep(0.2)

        if t_out.is_alive(): t_out.join(timeout=1)
        if t_err.is_alive(): t_err.join(timeout=1)

    except Exception as e:
        if p:
            _killpg(p)
        sendmessage(f"[Url-Watcher] ❌ Failed: {' '.join(cmd_list)} - {e}", colour="RED")



def run_waybackurls(subdomain: str, on_line):
    sendmessage(f"[Url-Watcher] ℹ️ Starting Waybackurls for '{subdomain}'...")
    run_command(["waybackurls", subdomain], on_line=on_line)


def run_katana(subdomain: str, on_line):
    sendmessage(f"[Url-Watcher] ℹ️ Starting Katana for '{subdomain}'...")
    run_command(["nice-katana", subdomain], on_line=on_line)


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
        else:
            new_body_hash = ""

        try:
            resp = requests.get(url, timeout=10)
            status = resp.status_code
        except requests.RequestException:
            status = None

        obj, created = Url.objects.get_or_create(
            subdomain=subdomain_obj.discovered_subdomain,
            path=clean_url.path,
            defaults={
                "tool": tool,
                "query": clean_url.query,
                "ext": matched_ext,
                "url": url,
                "body_hash": new_body_hash,
                "status": status,
            },
        )

        if created:
            obj.label = "new"
            obj.save()


        if isNewUrl : 
            obj2, created2 = NewUrl.objects.get_or_create(
                subdomain=subdomain_obj.discovered_subdomain,
                path=clean_url.path,
                defaults={
                    "tool": tool,
                   "query": clean_url.query,
                   "ext": matched_ext,
                   "url": url,
                   "body_hash": new_body_hash,
                    "status": status,
                },
             )

            if created2:
                obj2.label = "new"
                obj2.save()

    sendmessage(f"[Url-Watcher] ℹ️ Starting Url Discovery Assets (label : {label})", colour="CYAN")

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

        elif subdomain.label == "available":
            run_katana(
                subdomain.httpx_result,
                on_line=lambda url, sub=subdomain: insert_url(sub, url , True, 'katana')
            )


    sendmessage(f"[Urls-Watcher] ✅ URLs Discovery Successfully Done" , colour="CYAN")


def detect_urls_changes(self):
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Detect URLs Changes (Body-Hash , Query-Changes , Status-Changes)" , colour="CYAN")

    urls = Url.objects.filter(label='available' , subdomain__wildcard__tools__tool_name="daily_narrow_monitoring")
    for url in urls:
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
                }
            )
            if url.ext in EXTS : 
                new_body_hash = hashlib.sha256(response.content).hexdigest()
            else : 
                new_body_hash = ''
            new_status = str(response.status_code)
            new_query = url.query 
        except requests.RequestException:
            continue
        

        if url.body_hash != new_body_hash:
            changes['body_hash_change'] = f"{url.body_hash} -> {new_body_hash}"
            url.body_hash = new_body_hash

        if url.status != new_status:
            changes['status_change'] = f"{url.status} -> {new_status}"
            url.status = new_status

        if url.query != new_query:
            changes['query_change'] = f"{url.query} -> {new_query}"
            url.query = new_query

        if changes:
            UrlChanges.objects.create(
                url=url,
                query_change=changes.get('query_change', ''),
                body_hash_change=changes.get('body_hash_change', ''),
                status_change=changes.get('status_change', ''),
                label="new",
                ext=url.ext
            )
            url.label = 'new'
            url.save(update_fields=['body_hash', 'status', 'query', 'label'])

    sendmessage(f"[Urls-Watcher] ✅ Detect URLs Changes Successfully Done" , colour="CYAN")

def discover_parameter(self , label):
    sendmessage(f"[Urls-Watcher] ℹ️ Starting Discover Parameters on Assets (label: {label})" , colour="CYAN")
    
    def parameters_insert_database(subdomain , parameters):
        for parameter in parameters :
            obj, created = SubdomainParameter.objects.get_or_create(
                subdomain = subdomain,
                parameter = parameter
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
            sendmessage(f"[Url-Watcher] ❌ Failed to decode JSON for {url_instance}: {str(e)}", colour="RED")
        except FileNotFoundError:
            sendmessage(f"[Url-Watcher] ❌ JSON file not found: {json_file_path}", colour="RED")
        except Exception as e:
            sendmessage(f"[Url-Watcher] ❌ Failed to save parameters for {url_instance}: {str(e)}", colour="RED")

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
                    sendmessage(f"[Url-Watcher] ⏱ Timeout X8 {url} with {method}", colour="RED")
                    continue 

                if process.returncode != 0:
                    sendmessage(f"[Url-Watcher] ❌ X8 failed on {url} with {method}: {stderr.strip()}", colour="RED")
                    continue

                save_x8_output_from_file(url_instance , output_file, url)

            except Exception as e:
                sendmessage(f"[Url-Watcher] ❌ Unexpected error X8 {url} with {method}: {str(e)}", colour="RED")

    sendmessage(f"[Urls-Watcher] ℹ️ Starting Fuzz Parameters on URLs (label: {label})", colour="CYAN")


    if label == 'new' : 
        subdomains = SubdomainHttpx.objects.filter(label=label)
    else : 
        subdomains = SubdomainHttpx.objects.filter(label=label, discovered_subdomain__wildcard__tools__tool_name="daily_narrow_monitoring")


    for subdomain in subdomains:
        parameters = subdomain.discovered_subdomain.subdomainparameter_set.values_list('parameter', flat=True)
        read_write_list(list(parameters), f"{OUTPUT_PATH}/parameters.txt", 'w')

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
            run_x8(url, url.url, f"{OUTPUT_PATH}/parameters.txt", headers)

    sendmessage(f"[Urls-Watcher] ✅ Fuzzing Parameters on URLs Successfully Done" , colour="CYAN")



@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*12, time_limit=60*60*13)
def discover_urls_task(self, label):
    return discover_urls(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*12, time_limit=60*60*13)
def discover_parameter_task(self, label):
    return discover_parameter(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*12, time_limit=60*60*13)
def fuzz_parameters_on_urls_task(self, label):
    return fuzz_parameters_on_urls(self, label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*12, time_limit=60*60*13)
def vulnerability_monitor_task(self, label):
    return vulnerability_monitor(label)

@shared_task(bind=True, acks_late=True, soft_time_limit=60*60*12, time_limit=60*60*13)
def detect_urls_changes_task(self):
    return detect_urls_changes(self)



@shared_task
def notify_done():
    sendmessage("[Urls-Watcher] ✅ URL Monitoring Successfully Done", colour="CYAN")



@shared_task(bind=True, acks_late=True)
def url_monitor(self):
    clear_labels(self)
    sendmessage("[Url-Watcher] ⚠️ Vulnerability Discovery Will be Started Please add Valid Headers ⚠️")

    workflow = chain(
        discover_urls_task.s('new'),
        discover_parameter_task.si('new'),
        fuzz_parameters_on_urls_task.si('new'),
        vulnerability_monitor_task.si('new'),

        discover_urls_task.si('available'),
        discover_parameter_task.si('available'),
        fuzz_parameters_on_urls_task.si('available'),
        vulnerability_monitor_task.si('available'),
        
        detect_urls_changes_task.si(),
        notify_done.si()
    )
    workflow.apply_async()
