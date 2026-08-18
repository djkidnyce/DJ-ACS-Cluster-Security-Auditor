"""Generate the figures used in the ACS documentation.

These are annotated interface illustrations, not photographic screenshots. They are drawn
from the real element labels, colours and layout of the two HTML pages so they match what
the operator sees, while staying legible at print size and reproducible from source.
"""
import cairosvg, os

BG="#0d1117"; PANEL="#161b22"; PANEL2="#1c2330"; BORDER="#30363d"
TEXT="#e6edf3"; MUTED="#8b949e"; ACC="#58a6ff"
CRIT="#f85149"; HIGH="#f0883e"; MED="#d4a72c"; LOW="#3fb950"
FONT="DejaVu Sans, Segoe UI, Arial, sans-serif"
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"figures")

def esc(s): return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

def hdr(w, title, sub):
    return (f'<rect x="0" y="0" width="{w}" height="62" fill="#1f6feb"/>'
            f'<path d="M26 12 l17 6 v13 c0 10 -7 17 -17 22 c-10 -5 -17 -12 -17 -22 v-13 z" fill="#fff" opacity=".95"/>'
            f'<path d="M19 30 l6 6 l11 -12" stroke="#1f6feb" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<text x="56" y="27" font-size="17" font-weight="bold" fill="#fff">{esc(title)}</text>'
            f'<text x="56" y="47" font-size="11.5" fill="#cfe1ff">{esc(sub)}</text>')

def card(x,y,w,h,num,lbl,colour=TEXT):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="7" fill="{PANEL}" stroke="{BORDER}"/>'
            f'<text x="{x+12}" y="{y+30}" font-size="20" font-weight="bold" fill="{colour}">{esc(num)}</text>'
            f'<text x="{x+12}" y="{y+48}" font-size="9" fill="{MUTED}">{esc(lbl.upper())}</text>')

def sevchip(x,y,label):
    cols={"CRITICAL":("#67060c","#ffb3ad"),"HIGH":("#5a2d0c","#ffc999"),
          "MEDIUM":("#4d3800","#f2d24b"),"LOW":("#0f3d1e","#7ee2a8")}
    bg,fg=cols[label]
    w=len(label)*6.4+16
    return (f'<rect x="{x}" y="{y-10}" width="{w}" height="15" rx="7" fill="{bg}"/>'
            f'<text x="{x+w/2}" y="{y+1}" font-size="8.5" font-weight="bold" fill="{fg}" text-anchor="middle">{label}</text>')

def callout(x,y,n,text,w=250):
    return (f'<circle cx="{x}" cy="{y}" r="11" fill="{ACC}"/>'
            f'<text x="{x}" y="{y+4}" font-size="12" font-weight="bold" fill="#fff" text-anchor="middle">{n}</text>'
            f'<text x="{x+18}" y="{y+4}" font-size="11.5" fill="{TEXT}">{esc(text)}</text>')

def render(name, svg, w, h, scale=2):
    path=os.path.join(OUT,name)
    open(path+".svg","w").write(svg)
    cairosvg.svg2png(url=path+".svg", write_to=path+".png",
                     output_width=int(w*scale), output_height=int(h*scale))
    print("  ", name+".png", f"{int(w*scale)}x{int(h*scale)}")

os.makedirs(OUT, exist_ok=True)
print("Rendering figures")

# ---------------------------------------------------------------- Figure 1
W,H=1160,700
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',
   hdr(W,"DJ's ACS Auditor","Audit manifests against Red Hat ACS policy, score, rank, and cross check against your cluster")]
p.append(f'<rect x="24" y="80" width="{W-48}" height="86" rx="9" fill="{PANEL}" stroke="{BORDER}" stroke-dasharray="6 4"/>')
p.append(f'<text x="{W/2}" y="112" font-size="14" font-weight="bold" fill="{TEXT}" text-anchor="middle">Drop your YAML manifests here, or a whole folder</text>')
p.append(f'<text x="{W/2}" y="132" font-size="11" fill="{MUTED}" text-anchor="middle">Add an ACS violation export (.json) to cross check against your running cluster</text>')
for i,(lbl,xx) in enumerate([("Browse files",420),("Browse folder",530),("Load a deliberately bad sample",650)]):
    wdt=len(lbl)*6.6+22
    p.append(f'<rect x="{xx}" y="142" width="{wdt}" height="20" rx="5" fill="{PANEL2}" stroke="{BORDER}"/>')
    p.append(f'<text x="{xx+wdt/2}" y="156" font-size="10" fill="{TEXT}" text-anchor="middle">{esc(lbl)}</text>')
p.append(callout(40,123,"1","Drop files, or a folder",0))
# cards
cards=[("15","Posture, grade F",CRIT),("83","After auto fixes",LOW),("17","Findings",TEXT),
       ("2","Critical",CRIT),("5","High",HIGH),("6","Medium",MED),("1","Low",LOW),
       ("14","Auto fixable",TEXT),("3","Need a decision",TEXT),("2","Confirmed live",CRIT)]
x=24
for num,lbl,col in cards:
    p.append(card(x,186,108,62,num,lbl,col)); x+=112
p.append(callout(40,272,"2","Posture now, and after the automatic fixes are applied",0))
# category bars
p.append(f'<rect x="24" y="292" width="{W-48}" height="150" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="315" font-size="11" font-weight="bold" fill="{ACC}">POSTURE BY ACS CATEGORY</text>')
rows=[("Privileges",8,88),("Docker CIS",22,100),("Kubernetes",46,72),("Network",30,70),("Security Best Practices",0,100),("Resource Management",0,100)]
yy=336
for lbl,now,aft in rows:
    p.append(f'<text x="196" y="{yy+4}" font-size="10" fill="{MUTED}" text-anchor="end">{esc(lbl)}</text>')
    p.append(f'<rect x="206" y="{yy-7}" width="330" height="12" rx="3" fill="#21262d"/>')
    c=LOW if now>=80 else (MED if now>=60 else CRIT)
    p.append(f'<rect x="206" y="{yy-7}" width="{int(330*now/100)}" height="12" rx="3" fill="{c}"/>')
    p.append(f'<rect x="548" y="{yy-7}" width="330" height="12" rx="3" fill="#21262d"/>')
    c2=LOW if aft>=80 else (MED if aft>=60 else CRIT)
    p.append(f'<rect x="548" y="{yy-7}" width="{int(330*aft/100)}" height="12" rx="3" fill="{c2}"/>')
    p.append(f'<text x="894" y="{yy+4}" font-size="10" fill="{TEXT}">{now} &#8594; {aft}</text>')
    yy+=18
p.append(f'<text x="371" y="{yy+6}" font-size="9" fill="{MUTED}" text-anchor="middle">NOW</text>')
p.append(f'<text x="713" y="{yy+6}" font-size="9" fill="{MUTED}" text-anchor="middle">AFTER AUTO FIXES</text>')
p.append(callout(40,470,"3","Same denominator on both sides, so the two numbers are comparable",0))
# findings table
p.append(f'<rect x="24" y="492" width="{W-48}" height="176" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="514" font-size="11" font-weight="bold" fill="{ACC}">FINDINGS</text>')
cols=[("SEVERITY",44),("SCORE",148),("POLICY",206),("OBJECT",560),("FINDING",760),("FIX",1046)]
for c,cx in cols: p.append(f'<text x="{cx}" y="534" font-size="8.5" fill="{MUTED}">{c}</text>')
p.append(f'<line x1="34" y1="540" x2="{W-34}" y2="540" stroke="{BORDER}"/>')
rows2=[("CRITICAL","9.3","ACS.011  Mounting Container Runtime Socket","Deployment/payments-api","mounts /var/run/docker.sock","Manual",MED),
       ("CRITICAL","9.1","ACS.010  Environment Variable Contains Secret","Deployment/payments-api","env DB_PASSWORD holds a credential","Auto",LOW),
       ("HIGH","8.8","ACS.001  Privileged Container","Deployment/payments-api","container api runs privileged","Auto",LOW),
       ("HIGH","8.1","ACS.004  Host network configured","Deployment/payments-api","pod sets hostNetwork true","Auto",LOW),
       ("MEDIUM","5.9","ACS.015  Latest tag","Deployment/payments-api","image uses the latest tag","Manual",MED)]
yy=560
for sev,sc,pol,obj,det,fix,fc in rows2:
    p.append(sevchip(44,yy,sev))
    p.append(f'<text x="148" y="{yy+3}" font-size="10" font-weight="bold" fill="{TEXT}">{sc}</text>')
    p.append(f'<text x="212" y="{yy+3}" font-size="10" fill="{ACC}">{esc(pol)}</text>')
    p.append(f'<text x="560" y="{yy+3}" font-size="9.5" fill="{TEXT}">{esc(obj)}</text>')
    p.append(f'<text x="760" y="{yy+3}" font-size="9.5" fill="{MUTED}">{esc(det)}</text>')
    wf=len(fix)*6+14
    p.append(f'<rect x="1046" y="{yy-9}" width="{wf}" height="14" rx="7" fill="none" stroke="{fc}"/>')
    p.append(f'<text x="{1046+wf/2}" y="{yy+2}" font-size="8.5" fill="{fc}" text-anchor="middle">{fix}</text>')
    yy+=22
p.append(callout(40,684,"4","Ranked worst first. Auto means safe to apply, Manual needs a decision",0))
p.append('</svg>')
render("fig1_auditor_overview","\n".join(p),W,H)

# ---------------------------------------------------------------- Figure 2
W,H=1160,600
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',
   hdr(W,"Connecting to a live cluster","Pull violations from ACS Central, or pull the running workloads from the OpenShift API")]
p.append(f'<rect x="24" y="80" width="{W-48}" height="300" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="103" font-size="11" font-weight="bold" fill="{ACC}">OR PULL STRAIGHT FROM YOUR CLUSTER</text>')
for i,(lbl,on) in enumerate([("ACS Central",True),("OpenShift API",False)]):
    xx=42+i*118; wdt=104
    p.append(f'<rect x="{xx}" y="115" width="{wdt}" height="24" rx="6" fill="{PANEL2}" stroke="{ACC if on else BORDER}"/>')
    p.append(f'<text x="{xx+wdt/2}" y="131" font-size="11" fill="{ACC if on else TEXT}" font-weight="{"bold" if on else "normal"}" text-anchor="middle">{esc(lbl)}</text>')
fields=[("ACS CENTRAL URL","https://central-stackrox.apps.example.com",42),
        ("API TOKEN","••••••••••••••••••••••••",412),
        ("FILTER (OPTIONAL ACS QUERY)","Severity:CRITICAL_SEVERITY",782)]
for lbl,val,xx in fields:
    p.append(f'<text x="{xx}" y="167" font-size="8.5" fill="{MUTED}">{lbl}</text>')
    p.append(f'<rect x="{xx}" y="174" width="336" height="28" rx="6" fill="{PANEL2}" stroke="{BORDER}"/>')
    p.append(f'<text x="{xx+10}" y="193" font-size="10.5" fill="{TEXT}">{esc(val)}</text>')
p.append(f'<rect x="42" y="216" width="126" height="26" rx="6" fill="#1f6feb"/>')
p.append(f'<text x="105" y="233" font-size="11" font-weight="bold" fill="#fff" text-anchor="middle">Fetch violations</text>')
p.append(f'<rect x="122" y="216" width="228" height="26" rx="6" fill="{PANEL2}" stroke="{BORDER}"/>')
p.append(f'<text x="290" y="233" font-size="11" fill="{TEXT}" text-anchor="middle">Show the offline command instead</text>')
p.append(callout(430,229,"1","Use this when the browser is blocked",0))
p.append(f'<rect x="42" y="258" width="{W-84}" height="72" rx="7" fill="{PANEL2}"/>')
p.append(f'<rect x="42" y="258" width="3" height="72" fill="{MED}"/>')
p.append(f'<text x="58" y="278" font-size="11" font-weight="bold" fill="{TEXT}">How your token is handled.</text>')
for i,line in enumerate([
  "It stays in a variable in this tab for the duration of the request, then the field is cleared.",
  "It is never written to storage, never logged, and never included in any file you download.",
  "Use a short lived, read only, least privileged token regardless."]):
    p.append(f'<text x="58" y="{296+i*15}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
p.append(callout(40,352,"2","Read only. Nothing is ever written back to the cluster",0))
# CORS explainer
p.append(f'<rect x="24" y="398" width="{W-48}" height="186" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="421" font-size="11" font-weight="bold" fill="{ACC}">IF THE BROWSER BLOCKS THE CALL</text>')
p.append(f'<text x="42" y="443" font-size="11" fill="{TEXT}">A page opened from a file:// URL has a null origin. Neither ACS Central nor the OpenShift API sends a CORS header that allows it,</text>')
p.append(f'<text x="42" y="460" font-size="11" fill="{TEXT}">so the browser blocks the response before the page sees it. That is the browser protecting you, not a defect. Two ways forward:</text>')
p.append(f'<text x="52" y="486" font-size="11" fill="{LOW}">A.  Serve the page from an allowed origin</text>')
p.append(f'<text x="70" y="503" font-size="10.5" fill="{MUTED}">OpenShift: add it to spec.additionalCORSAllowedOrigins on the APIServer resource.</text>')
p.append(f'<text x="70" y="519" font-size="10.5" fill="{MUTED}">ACS: serve the page from Central\'s own route, or put both behind one reverse proxy.</text>')
p.append(f'<text x="52" y="543" font-size="11" fill="{LOW}">B.  Use the offline route, which never involves the browser</text>')
p.append(f'<rect x="70" y="551" width="1000" height="22" rx="5" fill="{PANEL2}" stroke="{BORDER}"/>')
p.append(f'<text x="80" y="566" font-size="10" font-family="monospace" fill="{TEXT}">curl -sk -H "Authorization: Bearer $ROX_API_TOKEN" "https://central.../v1/alerts" -o acs_alerts.json   # then drop the file on the page</text>')
p.append('</svg>')
render("fig2_live_connect","\n".join(p),W,H)

# ---------------------------------------------------------------- Figure 3
W,H=1160,700
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',
   hdr(W,"DJ's ACS Remediation","Apply fixes to YAML with a preview and a confirmation. Nothing is executed, nothing touches a cluster")]
p.append(f'<rect x="24" y="80" width="{W-48}" height="96" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="103" font-size="11" font-weight="bold" fill="{ACC}">HOW DO YOU WANT TO WORK THROUGH THESE</text>')
btns=[("Step through one by one",42,168,True),("Review and apply all auto fixes",218,208,False),
      ("Undo last",434,86,False),("Undo everything",528,116,False)]
for lbl,xx,wdt,prim in btns:
    p.append(f'<rect x="{xx}" y="116" width="{wdt}" height="27" rx="6" fill="{"#1f6feb" if prim else PANEL2}" stroke="{"#1f6feb" if prim else BORDER}"/>')
    p.append(f'<text x="{xx+wdt/2}" y="134" font-size="11" fill="{"#fff" if prim else TEXT}" font-weight="{"bold" if prim else "normal"}" text-anchor="middle">{esc(lbl)}</text>')
p.append(f'<rect x="900" y="122" width="13" height="13" rx="3" fill={chr(34)}{PANEL2}{chr(34)} stroke="{BORDER}"/>')
p.append(f'<text x="920" y="133" font-size="10.5" fill="{MUTED}">Skip the confirmation prompt</text>')
p.append(f'<text x="42" y="163" font-size="10.5" fill="{MUTED}">Every change is previewed as a diff and needs confirmation. Undo works one step at a time or all the way back.</text>')
p.append(callout(40,196,"1","Three ways to work. Stepping is the careful one",0))
# step modal
p.append(f'<rect x="96" y="218" width="762" height="452" rx="11" fill="{PANEL}" stroke="{ACC}" stroke-width="2"/>')
p.append(f'<text x="122" y="248" font-size="12" font-weight="bold" fill="{TEXT}">Fix 3 of 14</text>')
p.append(f'<rect x="206" y="240" width="440" height="8" rx="4" fill="{PANEL2}"/>')
p.append(f'<rect x="206" y="240" width="94" height="8" rx="4" fill="{ACC}"/>')
p.append(f'<text x="666" y="248" font-size="10" fill="{MUTED}">2 applied so far</text>')
p.append(f'<text x="122" y="278" font-size="15" font-weight="bold" fill="{TEXT}">Privileged Container</text>')
p.append(f'<text x="122" y="298" font-size="11" fill="{ACC}">ACS.001</text>')
p.append(sevchip(174,297,"HIGH"))
p.append(f'<rect x="231" y="287" width="72" height="14" rx="7" fill="none" stroke="{CRIT}"/>')
p.append(f'<text x="267" y="298" font-size="8.5" fill="{CRIT}" text-anchor="middle">live in ACS</text>')
kv=[("Object","Deployment/payments-api"),
    ("File","live/prod/deployment-payments-api.yaml"),
    ("Found",'Container "api" (containers) runs privileged'),
    ("Why it matters","Privileged containers can reach all host devices and escape isolation entirely."),
    ("What changes",'container "api": privileged true to false'),
    ("Standards","CIS 5.2.1  |  NIST 800-53: AC-6, CM-7  |  PSS: Baseline  |  STIG: verify")]
yy=326
for k,v in kv:
    p.append(f'<text x="122" y="{yy}" font-size="10.5" fill="{MUTED}">{esc(k)}</text>')
    p.append(f'<text x="246" y="{yy}" font-size="10.5" fill="{TEXT}">{esc(v)}</text>')
    yy+=19
p.append(callout(884,300,"2","Full advisory before",0))
p.append(f'<text x="902" y="320" font-size="11.5" fill="{TEXT}">you decide</text>')
# diff
p.append(f'<rect x="122" y="452" width="712" height="118" rx="7" fill="#0d1117" stroke="{BORDER}"/>')
dl=[(" ","        securityContext:"),("-","          privileged: true"),
    ("+","          privileged: false"),(" ","          capabilities:"),(" ","            drop:"),(" ","              - ALL")]
yy=474
for tt,txt in dl:
    if tt=="-": p.append(f'<rect x="123" y="{yy-12}" width="710" height="17" fill="#67060c"/>')
    if tt=="+": p.append(f'<rect x="123" y="{yy-12}" width="710" height="17" fill="#0f3d1e"/>')
    col="#ffb3ad" if tt=="-" else ("#7ee2a8" if tt=="+" else MUTED)
    p.append(f'<text x="134" y="{yy}" font-size="11" font-family="monospace" xml:space="preserve" fill="{col}">{esc(tt+" "+txt).replace(chr(32),chr(38)+chr(35)+chr(49)+chr(54)+chr(48)+chr(59))}</text>')
    yy+=17
p.append(callout(884,494,"3","The real diff, not a",0))
p.append(f'<text x="902" y="514" font-size="11.5" fill="{TEXT}">description of one</text>')
sbtn=[("Stop here",486,92,False),("Skip this one",588,110,False),("Apply and continue",708,122,True)]
for lbl,xx,wdt,prim in sbtn:
    p.append(f'<rect x="{xx}" y="596" width="{wdt}" height="28" rx="6" fill="{"#1f6feb" if prim else PANEL2}" stroke="{"#1f6feb" if prim else BORDER}"/>')
    p.append(f'<text x="{xx+wdt/2}" y="615" font-size="11" fill="{"#fff" if prim else TEXT}" font-weight="{"bold" if prim else "normal"}" text-anchor="middle">{esc(lbl)}</text>')
p.append(callout(122,610,"4","Apply, skip, or stop. Nothing happens until you choose",0))
p.append(f'<text x="122" y="654" font-size="10.5" fill="{MUTED}">Manual findings never appear in this queue. They are explained in the table and left alone.</text>')
p.append('</svg>')
render("fig3_step_through","\n".join(p),W,H)

# ---------------------------------------------------------------- Figure 4
W,H=1160,512
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',
   hdr(W,"What comes out","Five ways to take the result. All of them are files you review, none of them run anything")]
outs=[("Patched YAML, ZIP","Your folder structure preserved,\nplus a change log","#1f6feb"),
      ("One combined YAML","Every document in a single file","#30363d"),
      ("Merge patches","Only the changed fields, keyed\non container name. For Helm\nand Kustomize templates","#30363d"),
      ("Full diff","Copied to the clipboard for a\nticket or a review","#30363d"),
      ("Change log","Every change, why, and the\nstandards behind it","#30363d")]
x=32
for title,body,col in outs:
    p.append(f'<rect x="{x}" y="92" width="212" height="132" rx="9" fill="{PANEL}" stroke="{col}"/>')
    p.append(f'<text x="{x+16}" y="120" font-size="12.5" font-weight="bold" fill="{TEXT}">{esc(title)}</text>')
    for i,line in enumerate(body.split("\n")):
        p.append(f'<text x="{x+16}" y="{144+i*16}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
    x+=224
p.append(f'<rect x="32" y="248" width="{W-64}" height="132" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="52" y="272" font-size="11" font-weight="bold" fill="{ACC}">EXAMPLE MERGE PATCH</text>')
mp=[("spec:",TEXT),("  template:",TEXT),("    spec:",TEXT),("      containers:",TEXT),
    ("        - securityContext:",LOW),("            privileged: false",LOW),("          name: api",LOW)]
NB=chr(38)+chr(35)+chr(49)+chr(54)+chr(48)+chr(59)
for i,(line,col) in enumerate(mp):
    p.append(f'<text x="52" y="{290+i*15}" font-size="10" font-family="monospace" xml:space="preserve" fill="{col}">{esc(line).replace(chr(32),NB)}</text>')
p.append(f'<text x="560" y="292" font-size="10.5" fill="{MUTED}">Only the field that changed, plus the container name.</text>')
p.append(f'<text x="560" y="308" font-size="10.5" fill="{MUTED}">Kubernetes merges these arrays on name, so this patch</text>')
p.append(f'<text x="560" y="324" font-size="10.5" fill="{MUTED}">cannot clobber a field that drifted since the scan.</text>')
p.append(f'<rect x="32" y="398" width="{W-64}" height="88" rx="9" fill="{PANEL2}"/>')
p.append(f'<rect x="32" y="398" width="3" height="88" fill="{LOW}"/>')
p.append(f'<text x="52" y="422" font-size="12" font-weight="bold" fill="{TEXT}">No command is ever run to remediate a finding.</text>')
for i,line in enumerate([
  "Fixes are edits to YAML text made in your browser. Nothing calls oc, kubectl or roxctl. Nothing is applied to a cluster.",
  "The tool contains no exec, no eval and no Function constructor, and the test suite asserts that.",
  "You review the output and deploy it through whatever process you already trust."]):
    p.append(f'<text x="52" y="{442+i*15}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
p.append('</svg>')
render("fig4_outputs","\n".join(p),W,H)
