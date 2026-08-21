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
   hdr(W,"Getting the data out of ACS","The scripts run where the cluster is reachable. The page reads what they write.")]
# why the browser is not in this picture
p.append(f'<rect x="24" y="80" width="{W-48}" height="128" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<rect x="24" y="80" width="3" height="128" fill="{MED}"/>')
p.append(f'<text x="44" y="106" font-size="12" font-weight="bold" fill="{TEXT}">The pages do not connect to anything, and that is deliberate.</text>')
for i,line in enumerate([
  "A page opened from a file has a null origin. Neither ACS Central nor the OpenShift API sends a header that permits it, so the browser",
  "blocks the response before the page ever sees it. An in browser connector could not work from here no matter how it was written.",
  "Building one anyway meant asking you to paste a live ACS API token into a browser tab in exchange for a request that then failed.",
  "The token risk was real and the benefit was zero, so the connectors were removed rather than mitigated."]):
    p.append(f'<text x="44" y="{130+i*18}" font-size="11" fill="{MUTED}">{esc(line)}</text>')

# the three steps
def stepbox(x,y,w,h,n,title,lines,accent=ACC):
    o=[f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" fill="{PANEL}" stroke="{BORDER}"/>',
       f'<circle cx="{x+26}" cy="{y+28}" r="13" fill="{accent}"/>',
       f'<text x="{x+26}" y="{y+33}" font-size="13" font-weight="bold" fill="#fff" text-anchor="middle">{n}</text>',
       f'<text x="{x+48}" y="{y+33}" font-size="13" font-weight="bold" fill="{TEXT}">{esc(title)}</text>']
    for i,l in enumerate(lines):
        mono = l.startswith("$")
        fam = ' font-family="monospace"' if mono else ''
        col = TEXT if mono else MUTED
        o.append(f'<text x="{x+18}" y="{y+58+i*17}" font-size="10.5" fill="{col}"{fam}>{esc(l)}</text>')
    return "".join(o)

p.append(stepbox(24,228,352,214,"1","Run the preflight",[
  "$ ./scripts/acs_preflight.sh",
  "",
  "Checks the endpoint is reachable, the token",
  "is valid, TLS verifies, and the token can",
  "actually read Alert, Image and Deployment.",
  "",
  "A token scoped only to Alert returns 403 on",
  "the vulnerability export while violations keep",
  "working, which is a confusing way to see",
  "nothing. This catches it in one line."]))

p.append(stepbox(404,228,352,214,"2","Pull everything",[
  "$ ./scripts/acs_pull_all.sh"]))
files=[("00_auth_status.json","who the token is"),
       ("01_alerts_list.json","every violation"),
       ("02_alerts_full.json","with the violation text"),
       ("03_vuln_workloads.ndjson","running images"),
       ("04_all_images.ndjson","deployed or not"),
       ("05_nodes.ndjson","node CVEs"),
       ("06_snoozed.ndjson","what was deferred")]
for i,(fn,desc) in enumerate(files):
    yy=303+i*17
    p.append(f'<text x="422" y="{yy}" font-size="9.5" font-family="monospace" fill="{TEXT}">{esc(fn)}</text>')
    p.append(f'<text x="606" y="{yy}" font-size="9.5" fill="{MUTED}">{esc(desc)}</text>')

p.append(stepbox(784,228,352,214,"3","Drop them on the page",[
  "All of them at once, in any order.",
  "",
  "They accumulate rather than replace each",
  "other. A violation that arrives twice, once",
  "slim from the list and once hydrated from",
  "the detail endpoint, is deduplicated and",
  "the hydrated copy is kept.",
  "",
  "Nothing is uploaded. The file is read in",
  "the tab and never leaves the machine."],LOW))

for xx in (386,766):
    p.append(f'<path d="M{xx} 335 l14 0" stroke="{MUTED}" stroke-width="2"/>')
    p.append(f'<path d="M{xx+14} 335 l-6 -5 l0 10 z" fill="{MUTED}"/>')

# token handling in the shell
p.append(f'<rect x="24" y="462" width="{W-48}" height="122" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="44" y="488" font-size="11" font-weight="bold" fill="{ACC}">WHY THE SHELL IS THE SAFER PLACE FOR THE TOKEN</text>')
for i,line in enumerate([
  "The scripts read the token from the environment or prompt for it without echo. It is never passed as an argument, so it does not appear in ps",
  "output where any other user on the box could read it, and it does not land in your shell history. TLS is verified by default and --cacert is",
  "supported for a private CA. Every call is a GET. There is no code path in any script that writes to a cluster.",
  "PowerShell equivalents are in scripts/acs_pull_all.ps1, and scripts/acs_pull_over_ssh.ps1 runs the pull on a jump host when Central is not",
  "reachable from your workstation at all."]):
    p.append(f'<text x="44" y="{510+i*17}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
p.append('</svg>')
render("fig2_pull_workflow","\n".join(p),W,H)

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

# ---------------------------------------------------------------- Figure 8
W,H=1160,912
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',
   hdr(W,"Violations from ACS","Every violation gets a row, and every row says what can be done about it")]

p.append(f'<rect x="24" y="80" width="{W-48}" height="400" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="104" font-size="11" font-weight="bold" fill="{ACC}">VIOLATIONS FROM ACS</text>')
# filters
filters=[("Your workloads",True),("Platform components",False),("Fixable only",False),
         ("Matched to a policy",True),("Unmatched",False)]
xx=42
for lbl,on in filters:
    wdt=len(lbl)*6.1+34
    p.append(f'<rect x="{xx}" y="116" width="14" height="14" rx="3" fill="{ACC if on else PANEL2}" stroke="{ACC if on else BORDER}"/>')
    if on: p.append(f'<path d="M{xx+3} {xx and 123} l3 3 l5 -6" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round"/>')
    p.append(f'<text x="{xx+21}" y="127" font-size="10.5" fill="{MUTED}">{esc(lbl)}</text>')
    xx+=wdt
p.append(f'<text x="{xx+10}" y="127" font-size="10.5" fill="{MUTED}">showing 4 of 6 violation(s): 4 on your workloads, 2 on platform components</text>')

cols=[("",42),("SEVERITY",70),("ACS POLICY",160),("OBJECT",396),("NAMESPACE",620),("STATE",744),("VIOLATION",820),("FIX",985)]
for lbl,cx in cols:
    p.append(f'<text x="{cx}" y="156" font-size="9" fill="{MUTED}" letter-spacing="1">{lbl}</text>')
p.append(f'<rect x="42" y="146" width="13" height="13" rx="3" fill="{PANEL2}" stroke="{ACC}"/>')
p.append(f'<line x1="45" y1="152" x2="52" y2="152" stroke="{ACC}" stroke-width="2"/>')
p.append(f'<line x1="42" y1="164" x2="{W-42}" y2="164" stroke="{BORDER}"/>')

rows=[("CRITICAL","ACS.001  Privileged Container","Deployment/payments-api","prod","ACTIVE",
       'Container "api" is privileged',"In your YAML",LOW),
      ("HIGH","ACS.004  Host Network","Deployment/edge-proxy","prod","ACTIVE",
       "Deployment uses the host network","Patch",ACC),
      ("HIGH","ACS.007  Root User","StatefulSet/cache","data","ACTIVE",
       "Container runs as root","Patch",ACC),
      ("MEDIUM","ACS.012  No Resource Limits","CronJob/nightly-etl","batch","ACTIVE",
       "No CPU or memory limit set","Need manifest",MED),
      ("HIGH","ACS.001  Privileged Container","DaemonSet/ovnkube-node","openshift-ovn-kube","ACTIVE",
       'Container "ovn-controller" is privileged',"Platform",CRIT)]
y=186
ticked={0:True,1:True,2:False,3:False}
for ri,(sev,pol,obj,ns,st,det,fix,fc) in enumerate(rows):
    if fix=="Platform":
        # disabled: there is no fix route, so it cannot be chosen
        p.append(f'<rect x="42" y="{y-9}" width="13" height="13" rx="3" fill="{BG}" stroke="{BORDER}"/>')
        p.append(f'<line x1="44" y1="{y-7}" x2="53" y2="{y+2}" stroke="{BORDER}" stroke-width="1.2"/>')
    else:
        on=ticked.get(ri,False)
        p.append(f'<rect x="42" y="{y-9}" width="13" height="13" rx="3" fill="{ACC if on else PANEL2}" stroke="{ACC if on else BORDER}"/>')
        if on:
            p.append(f'<path d="M45 {y-3} l3 3 l5 -6" stroke="#fff" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
    p.append(sevchip(70,y,sev))
    pid,pname=pol.split("  ",1)
    p.append(f'<text x="160" y="{y+1}" font-size="10.5" font-family="monospace" fill="{ACC}" font-weight="bold">{esc(pid)}</text>')
    p.append(f'<text x="216" y="{y+1}" font-size="10.5" fill="{TEXT}">{esc(pname)}</text>')
    p.append(f'<text x="396" y="{y+1}" font-size="10.5" fill="{TEXT}">{esc(obj)}</text>')
    if fix=="Platform":
        p.append(f'<rect x="556" y="{y-9}" width="56" height="13" rx="6" fill="none" stroke="{BORDER}"/>')
        p.append(f'<text x="584" y="{y+1}" font-size="8" fill="{MUTED}" text-anchor="middle">PLATFORM</text>')
    p.append(f'<text x="620" y="{y+1}" font-size="10.5" fill="{MUTED}">{esc(ns)}</text>')
    p.append(f'<text x="744" y="{y+1}" font-size="10.5" fill="{MUTED}">{esc(st)}</text>')
    p.append(f'<text x="820" y="{y+1}" font-size="9" fill="{MUTED}">{esc(det[:29])}</text>')
    wdt=len(fix)*6.2+18
    p.append(f'<rect x="985" y="{y-10}" width="{wdt}" height="15" rx="7" fill="none" stroke="{fc}"/>')
    p.append(f'<text x="{985+wdt/2}" y="{y+1}" font-size="9" fill="{fc}" text-anchor="middle">{esc(fix)}</text>')
    if fix=="Platform":
        ox=985+wdt+6
        p.append(f'<rect x="{ox}" y="{y-10}" width="52" height="15" rx="7" fill="none" stroke="{MUTED}" stroke-dasharray="2 2"/>')
        p.append(f'<text x="{ox+26}" y="{y+1}" font-size="8" fill="{MUTED}" text-anchor="middle">override</text>')
    p.append(f'<line x1="42" y1="{y+14}" x2="{W-42}" y2="{y+14}" stroke="{BORDER}"/>')
    y+=38

p.append(f'<text x="42" y="{y+16}" font-size="10.5" fill="{MUTED}">Click a row for the rationale, the standards it maps to, and the reasoning behind the fix route.</text>')
p.append(callout(53,y+50,"1","Tick what you want to fix. Nothing is selected until you select it.",0))
p.append(callout(53,y+80,"2","No route means no checkbox. Override the refusal if the object is yours.",0))

# routes
p.append(f'<rect x="24" y="500" width="{W-48}" height="152" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<text x="42" y="524" font-size="11" font-weight="bold" fill="{ACC}">WHAT EACH ROUTE MEANS</text>')
routes=[("In your YAML",LOW,"The manifest is loaded, so the fix is applied to it directly and you download the corrected file."),
        ("Patch",ACC,"No manifest for this object, so a strategic merge patch is drafted from the violation itself."),
        ("Need manifest",MED,"Fixable in principle, but the violation does not carry enough to draft a patch safely."),
        ("Human decision",MED,"The policy has no mechanical fix. Somebody has to decide."),
        ("Platform",CRIT,"Listed, refused by default. Override per object if you own it: see below."),
        ("Not modelled",MED,"No policy in the catalogue matches. Reported rather than dropped.")]
for i,(lbl,col,desc) in enumerate(routes):
    yy=546+i*17
    wdt=len(lbl)*6.2+18
    p.append(f'<rect x="42" y="{yy-10}" width="{wdt}" height="14" rx="7" fill="none" stroke="{col}"/>')
    p.append(f'<text x="{42+wdt/2}" y="{yy}" font-size="8.5" fill="{col}" text-anchor="middle">{esc(lbl)}</text>')
    p.append(f'<text x="{42+wdt+14}" y="{yy}" font-size="10.5" fill="{MUTED}">{esc(desc)}</text>')

# the output
# platform is sometimes a guess, and the row says which
p.append(f'<rect x="24" y="670" width="{W-48}" height="96" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<rect x="24" y="670" width="3" height="96" fill="{MED}"/>')
p.append(f'<text x="44" y="694" font-size="12" font-weight="bold" fill="{TEXT}">Platform is sometimes a guess, and the row tells you which</text>')
for i,line in enumerate([
  "ACS said so: the platformComponent field. Authoritative, because ACS knows what the cluster operators own. Overriding asks you to confirm first.",
  "Guessed from namespace: ACS did not send the field, so the namespace was matched instead. That guess is wrong in both directions, and your own",
  "workload in openshift-operators would be refused forever. Override it and the normal fix routes apply, per object, never globally."]):
    p.append(f'<text x="44" y="{716+i*17}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')

p.append(f'<rect x="24" y="784" width="{W-48}" height="104" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<rect x="24" y="784" width="3" height="104" fill="{LOW}"/>')
p.append(f'<text x="44" y="808" font-size="12" font-weight="bold" fill="{TEXT}">What "fix" produces: a YAML file for the ones you ticked, and nothing else.</text>')
for i,line in enumerate([
  "No command is run and no cluster is touched, on any surface, in any mode. Each drafted file names the object, the namespace and the policies it",
  "covers, and states on its face that it was built from a violation rather than from a manifest, so it needs verifying. An overridden one says that too.",
  "Test it against a namespace you do not care about, then apply it yourself. Report mode, the default, writes the account and no YAML at all.",
  "The report states how many of the imported violations were in scope, so a document covering a subset cannot be mistaken for one covering the cluster."]):
    p.append(f'<text x="44" y="{830+i*17}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
p.append('</svg>')
render("fig8_violations_panel","\n".join(p),W,H)
