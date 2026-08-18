"""Figure 7: the two ACS data planes, and why /v1/alerts looks empty."""
import cairosvg, os
BG="#0d1117"; PANEL="#161b22"; PANEL2="#1c2330"; BORDER="#30363d"
TEXT="#e6edf3"; MUTED="#8b949e"; ACC="#58a6ff"
CRIT="#f85149"; GRN="#3fb950"; AMB="#d4a72c"
FONT="DejaVu Sans, Segoe UI, Arial, sans-serif"; MONO="monospace"
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"figures")
def esc(s): return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def hdr(w,title,sub):
    return (f'<rect x="0" y="0" width="{w}" height="62" fill="#1f6feb"/>'
            f'<path d="M26 12 l17 6 v13 c0 10 -7 17 -17 22 c-10 -5 -17 -12 -17 -22 v-13 z" fill="#fff" opacity=".95"/>'
            f'<path d="M19 30 l6 6 l11 -12" stroke="#1f6feb" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<text x="56" y="27" font-size="17" font-weight="bold" fill="#fff">{esc(title)}</text>'
            f'<text x="56" y="47" font-size="11.5" fill="#cfe1ff">{esc(sub)}</text>')
DEFS=(f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
      f'<path d="M0 0 L10 5 L0 10 z" fill="{ACC}"/></marker>'
      f'<marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
      f'<path d="M0 0 L10 5 L0 10 z" fill="{CRIT}"/></marker></defs>')
def render(name,svg,w,h,scale=2):
    p=os.path.join(OUT,name); open(p+".svg","w").write(svg)
    cairosvg.svg2png(url=p+".svg", write_to=p+".png", output_width=int(w*scale), output_height=int(h*scale))
    print("  ",name+".png",f"{int(w*scale)}x{int(h*scale)}")
os.makedirs(OUT,exist_ok=True); print("Rendering figure 7")

W,H=1160,720
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',DEFS,
   hdr(W,"Two ACS data planes, two endpoints","Why an empty alert list tells you nothing about your CVE exposure")]

# Central
p.append(f'<rect x="430" y="86" width="300" height="58" rx="9" fill="#1f6feb" opacity=".18" stroke="{ACC}"/>')
p.append(f'<text x="580" y="110" font-size="14" font-weight="bold" fill="{TEXT}" text-anchor="middle">ACS Central</text>')
p.append(f'<text x="580" y="130" font-size="10.5" fill="{MUTED}" text-anchor="middle">one product, two completely separate stores</text>')
p.append(f'<line x1="500" y1="144" x2="330" y2="186" stroke="{ACC}" stroke-width="2" marker-end="url(#ah)"/>')
p.append(f'<line x1="660" y1="144" x2="830" y2="186" stroke="{ACC}" stroke-width="2" marker-end="url(#ah)"/>')

def plane(x,title,sub,ep,fields,colour,note):
    o=[f'<rect x="{x}" y="190" width="500" height="300" rx="10" fill="{PANEL2}" stroke="{BORDER}"/>',
       f'<rect x="{x}" y="190" width="500" height="4" rx="2" fill="{colour}"/>',
       f'<text x="{x+18}" y="220" font-size="14" font-weight="bold" fill="{TEXT}">{esc(title)}</text>',
       f'<text x="{x+18}" y="240" font-size="10.5" fill="{MUTED}">{esc(sub)}</text>',
       f'<rect x="{x+18}" y="252" width="464" height="26" rx="5" fill="{PANEL}" stroke="{BORDER}"/>',
       f'<text x="{x+28}" y="269" font-size="11" fill="{ACC}" font-family="{MONO}">{esc(ep)}</text>']
    yy=300
    for f in fields:
        o.append(f'<text x="{x+18}" y="{yy}" font-size="10.5" fill="{TEXT}" font-family="{MONO}">{esc(f)}</text>')
        yy+=17
    o.append(f'<rect x="{x+18}" y="{yy+4}" width="464" height="{478-yy-8}" rx="6" fill="{PANEL}" stroke="{BORDER}"/>')
    ty=yy+24
    for line in note:
        o.append(f'<text x="{x+28}" y="{ty}" font-size="10.5" fill="{MUTED}">{esc(line)}</text>')
        ty+=15
    return "".join(o)

p.append(plane(24,"1. Policy violations","A rule you or Red Hat wrote, and something broke it",
  "GET /v1/alerts",
  ["ListAlert {","  policy.name, policy.severity, policy.categories",
   "  lifecycleStage, state",
   "  commonEntityInfo.namespace   <-- not deployment.namespace",
   "  NO violations[]              <-- the detail is not here",
   "}"],ACC,
  ["The slim projection. It tells you WHICH policy fired and","where, but never WHY.",
   "For the violation text you must then call",
   "GET /v1/alerts/{id} per alert. This tool does that for you."]))

p.append(plane(636,"2. Image vulnerabilities","A CVE the scanner found in a package inside an image",
  "GET /v1/export/vuln-mgmt/workloads",
  ["NDJSON, one line per workload:","{\"result\": {",
   "  \"deployment\": {...}, \"livePods\": N,",
   "  \"images\": [{ scan.components[].vulns[] }]",
   "}}"],GRN,
  ["Streams, so res.json() fails on it. Read as text.",
   "Token needs read on Image AND Deployment. A token",
   "scoped only to Alert gets 403 here while /v1/alerts",
   "keeps working, which is a confusing way to see nothing."]))

# the trap
p.append(f'<rect x="24" y="506" width="1112" height="86" rx="9" fill="#2d0f10" stroke="{CRIT}"/>')
p.append(f'<text x="44" y="532" font-size="13" font-weight="bold" fill="#ffb3ad">The trap</text>')
p.append(f'<text x="44" y="553" font-size="11.5" fill="#f5c6c2">An image CVE is NOT a policy violation. It only produces an alert if somebody wrote a policy that fires on it, and most teams have not.</text>')
p.append(f'<text x="44" y="571" font-size="11.5" fill="#f5c6c2">So a cluster full of critical, actively exploited CVEs can return an empty /v1/alerts list. Empty is not clean. It is the wrong question.</text>')
p.append(f'<line x1="274" y1="490" x2="274" y2="506" stroke="{CRIT}" stroke-width="2" marker-end="url(#ar)"/>')
p.append(f'<line x1="886" y1="490" x2="886" y2="506" stroke="{CRIT}" stroke-width="2" marker-end="url(#ar)"/>')

# what the tool does with each
p.append(f'<rect x="24" y="608" width="546" height="92" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<rect x="24" y="608" width="4" height="92" rx="2" fill="{ACC}"/>')
p.append(f'<text x="44" y="632" font-size="12.5" font-weight="bold" fill="{TEXT}">What the tool does with violations</text>')
for i,l in enumerate(["Matches each one to a policy, then to the manifest line that",
                      "causes it. Auto fixes the safe ones as YAML text edits,",
                      "explains the rest. Never runs a command."]):
    p.append(f'<text x="44" y="{652+i*16}" font-size="10.5" fill="{MUTED}">{esc(l)}</text>')

p.append(f'<rect x="590" y="608" width="546" height="92" rx="9" fill="{PANEL}" stroke="{BORDER}"/>')
p.append(f'<rect x="590" y="608" width="4" height="92" rx="2" fill="{GRN}"/>')
p.append(f'<text x="610" y="632" font-size="12.5" font-weight="bold" fill="{TEXT}">What the tool does with CVEs</text>')
for i,l in enumerate(["Ranks them, points at the file declaring the image, flags git",
                      "against cluster drift, and emits a rebuild worklist grouped by",
                      "image. No auto fix: ACS knows fixed packages, not fixed tags."]):
    p.append(f'<text x="610" y="{652+i*16}" font-size="10.5" fill="{MUTED}">{esc(l)}</text>')

p.append('</svg>')
render("fig7_two_data_planes","".join(p),W,H)
print("done")
