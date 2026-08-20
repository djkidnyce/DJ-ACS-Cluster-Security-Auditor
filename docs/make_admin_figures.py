"""Figures for the administration guide. Drawn from the real file names and data flow."""
import cairosvg, os
BG="#0d1117"; PANEL="#161b22"; PANEL2="#1c2330"; BORDER="#30363d"
TEXT="#e6edf3"; MUTED="#8b949e"; ACC="#58a6ff"
GRN="#3fb950"; AMB="#d4a72c"; RED="#f85149"; PUR="#a371f7"
FONT="DejaVu Sans, Segoe UI, Arial, sans-serif"
OUT=os.path.join(os.path.dirname(os.path.abspath(__file__)),"figures")
def esc(s): return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
def hdr(w,title,sub):
    return (f'<rect x="0" y="0" width="{w}" height="62" fill="#1f6feb"/>'
            f'<path d="M26 12 l17 6 v13 c0 10 -7 17 -17 22 c-10 -5 -17 -12 -17 -22 v-13 z" fill="#fff" opacity=".95"/>'
            f'<path d="M19 30 l6 6 l11 -12" stroke="#1f6feb" stroke-width="3.5" fill="none" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<text x="56" y="27" font-size="17" font-weight="bold" fill="#fff">{esc(title)}</text>'
            f'<text x="56" y="47" font-size="11.5" fill="#cfe1ff">{esc(sub)}</text>')
def box(x,y,w,h,title,lines,accent=ACC,fill=PANEL,mono=False):
    o=[f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="{fill}" stroke="{BORDER}"/>',
       f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" fill="{accent}"/>',
       f'<text x="{x+16}" y="{y+22}" font-size="12.5" font-weight="bold" fill="{TEXT}">{esc(title)}</text>']
    yy=y+41
    for L in lines:
        f='monospace' if mono else FONT
        o.append(f'<text x="{x+16}" y="{yy}" font-size="10.5" fill="{MUTED}" font-family="{f}">{esc(L)}</text>')
        yy+=15
    return "".join(o)
def arrow(x1,y1,x2,y2,label="",colour=ACC,dash=""):
    d=f' stroke-dasharray="{dash}"' if dash else ""
    o=[f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{colour}" stroke-width="2"{d} marker-end="url(#ah)"/>']
    if label:
        mx,my=(x1+x2)/2,(y1+y2)/2
        w=len(label)*5.6+14
        o.append(f'<rect x="{mx-w/2}" y="{my-9}" width="{w}" height="17" rx="8" fill="{BG}" stroke="{BORDER}"/>')
        o.append(f'<text x="{mx}" y="{my+3}" font-size="9.5" fill="{TEXT}" text-anchor="middle">{esc(label)}</text>')
    return "".join(o)
DEFS=(f'<defs><marker id="ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
      f'<path d="M0 0 L10 5 L0 10 z" fill="{ACC}"/></marker></defs>')
def render(name,svg,w,h,scale=2):
    p=os.path.join(OUT,name); open(p+".svg","w").write(svg)
    cairosvg.svg2png(url=p+".svg", write_to=p+".png", output_width=int(w*scale), output_height=int(h*scale))
    print("  ",name+".png",f"{int(w*scale)}x{int(h*scale)}")
os.makedirs(OUT,exist_ok=True); print("Rendering admin figures")

# ---------------- Figure 5: architecture
W,H=1160,600
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',DEFS,
   hdr(W,"Architecture","One engine. Every surface reads it. Nothing duplicates policy logic.")]

p.append(box(310,84,540,62,"acs_policies.js   THE ENGINE",
  ["ACS.001 to ACS.020  |  checks, fixes, ACS import and matching, CVE model,",
   "violation fix routing, patch drafting, diff, citations, weights"],GRN,PANEL,True))

# fan out to the surfaces
for x in (170,470,770,1010):
    p.append(arrow(580,148,x if x!=580 else 580,196,"","#4b5563"))

surfaces=[(24,"dj_acs_auditor.html",["Read only. Scan, score,","cross check, violations","panel, export the report"]),
          (318,"dj_acs_remediation.html",["Preview, confirm, step","through, undo. Produces","YAML you download"]),
          (612,"acs_cli.js",["Headless. Same output,","for a pipeline. acs.sh,","acs.ps1, acs.cmd wrap it"]),
          (906,"test/*.cjs",["694 assertions against","the same engine every","surface loads"])]
for x,t,l in surfaces:
    p.append(box(x,196,230,110,t,l,PUR if t.startswith("test") else ACC))

# what talks to a cluster, and what does not
p.append(f'<rect x="24" y="330" width="1112" height="112" rx="10" fill="{PANEL2}" stroke="{BORDER}"/>')
p.append(f'<text x="44" y="356" font-size="11" font-weight="bold" fill="{ACC}">WHERE THE CLUSTER IS ACTUALLY CONTACTED</text>')
p.append(f'<text x="44" y="380" font-size="11" fill="{TEXT}">Nowhere above. The pages contain no network call at all, and the CLI reads files.</text>')
p.append(f'<text x="44" y="400" font-size="11" fill="{MUTED}">scripts/acs_pull_all.sh and its PowerShell, SSH and oc port forward variants issue every request, GET only, in a shell where</text>')
p.append(f'<text x="44" y="418" font-size="11" fill="{MUTED}">the token can be kept out of ps and out of history. Their output is dropped onto a page or passed to the CLI with --alerts.</text>')

p.append(f'<text x="24" y="470" font-size="10.5" fill="{MUTED}">vendor/  js-yaml 4.1.0 and JSZip 3.10.1, committed and verified by SHA-256. No package manager, no network, works air gapped.</text>')

p.append(f'<rect x="24" y="490" width="1112" height="86" rx="10" fill="{PANEL2}" stroke="{BORDER}"/>')
p.append(f'<rect x="24" y="490" width="3" height="86" fill="{GRN}"/>')
p.append(f'<text x="44" y="516" font-size="12" font-weight="bold" fill="{TEXT}">The rule this diagram exists to enforce</text>')
p.append(f'<text x="44" y="538" font-size="11" fill="{MUTED}">Never copy a check into a second file to make a surface work. If a surface cannot reach the engine, fix the loading, not the logic.</text>')
p.append(f'<text x="44" y="558" font-size="11" fill="{MUTED}">The failure this prevents: the page reports a finding, the pipeline does not, and nobody notices for months.</text>')
p.append('</svg>')
render("fig5_architecture","".join(p),W,H)

# ---------------- Figure 6: maintenance cycle
W,H=1160,560
p=[f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" font-family="{FONT}">',
   f'<rect width="{W}" height="{H}" fill="{BG}"/>',DEFS,
   hdr(W,"Maintenance cycle","What a maintainer runs, in order, and what gates the release")]
steps=[("1","Upgrade ACS",["Red Hat adds, renames and","re-weights default policies","between releases"],AMB),
       ("2","Diff the defaults",["ACS console vs","acs_policies.js","Watch the unmatched count"],AMB),
       ("3","Edit the engine",["acs_policies.js","check, fix, alias, citations,","weight. One file only"],ACC),
       ("4","Run the tests",["node test/run_tests.js","694, and prove any new","regression test fails first"],PUR),
       ("5","Release",["CHANGELOG.md, version stamp","git status --short","Then publish"],GRN)]
x=24
for i,(n,t,lines,col) in enumerate(steps):
    p.append(box(x,110,196,132,t,lines,col))
    p.append(f'<circle cx="{x+178}" cy="{124}" r="13" fill="{col}"/>')
    p.append(f'<text x="{x+178}" y="{129}" font-size="13" font-weight="bold" fill="#0d1117" text-anchor="middle">{n}</text>')
    if i<4: p.append(arrow(x+198,176,x+222,176))
    x+=229
p.append(f'<rect x="24" y="272" width="1112" height="1" fill="{BORDER}"/>')
p.append(box(24,292,542,120,"Gates that must pass before anything ships",
  ["All tests green. A red suite is a blocked release, not a warning.",
   "Version stamp matches package.json and the CHANGELOG entry.",
   "Vendored library SHA-256 values still match vendor/README.md.",
   "No exec, eval, or Function constructor anywhere in a shipped file.",
   "Projected posture equals a real rescan on the sample manifest set."],GRN))
p.append(box(590,292,546,120,"Things that quietly rot if nobody looks",
  ["ACS renames a default policy and the alias table falls behind.",
   "A STIG release changes a control id that a citation points at.",
   "A waiver expires and nobody notices the finding came back.",
   "The version constant in the HTML drifts from the CLI. It stamps",
   "every report, so a stale value misdates your evidence."],RED))
p.append(f'<rect x="24" y="438" width="1112" height="60" rx="8" fill="#0f2a17" stroke="#1a7f37"/>')
p.append(f'<text x="44" y="464" font-size="12.5" font-weight="bold" fill="#7ee2a8">The rule that holds the whole thing together</text>')
p.append(f'<text x="44" y="484" font-size="11" fill="#b9f0cd">Policy logic lives in exactly one file per toolset. Every GUI, CLI, and test loads that file. If you ever find yourself copying a check into a second place, stop.</text>')
p.append(f'<text x="24" y="530" font-size="10.5" fill="{MUTED}">Air gapped sites: run step 1 on a connected machine and carry the single generated file across. Steps 2 through 5 need no network.</text>')
p.append('</svg>')
render("fig6_maintenance","".join(p),W,560)
print("done")
