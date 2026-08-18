const { Paragraph, TextRun, HeadingLevel, AlignmentType, Table, TableRow, TableCell,
        WidthType, ShadingType, BorderStyle, ImageRun, PageBreak, LevelFormat,
        TableOfContents, Header, Footer, PageNumber } = require('docx');
const fs = require('fs');

const LETTER = { width: 12240, height: 15840 };
const ACC = '1F6FEB', DARK = '1C2430', MUT = '5A6472', LINE = 'D0D7DE',
      HEADBG = 'EEF3FA', WARNBG = 'FFF8E1', OKBG = 'EAF6EC', CRITBG = 'FDECEA';

function P(text, opts) {
  const o = opts || {};
  return new Paragraph({
    heading: o.heading, alignment: o.align, spacing: o.spacing || { after: 120 },
    border: o.border, shading: o.shading, indent: o.indent, numbering: o.numbering,
    pageBreakBefore: o.pageBreakBefore,
    children: [new TextRun({ text: text || '', bold: o.bold, italics: o.italics,
      size: o.size || 21, color: o.color, font: o.font })],
  });
}
function Rich(runs, opts) {
  const o = opts || {};
  return new Paragraph({
    heading: o.heading, alignment: o.align, spacing: o.spacing || { after: 120 },
    shading: o.shading, indent: o.indent, numbering: o.numbering, border: o.border,
    children: runs.map((r) => new TextRun({
      text: r.t, bold: r.b, italics: r.i, size: r.size || 21,
      color: r.c, font: r.f, break: r.br })),
  });
}
function Code(lines) {
  return lines.map((l, i) => new Paragraph({
    spacing: { after: i === lines.length - 1 ? 140 : 0, before: i === 0 ? 40 : 0 },
    shading: { type: ShadingType.CLEAR, fill: 'F4F6F8' },
    indent: { left: 240, right: 240 },
    children: [new TextRun({ text: l || ' ', font: 'Consolas', size: 17, color: '24292F' })],
  }));
}
function Note(kind, title, body) {
  const fill = kind === 'warn' ? WARNBG : kind === 'crit' ? CRITBG : kind === 'ok' ? OKBG : HEADBG;
  const bar = kind === 'warn' ? 'D4A72C' : kind === 'crit' ? 'CF222E' : kind === 'ok' ? '1A7F37' : ACC;
  const out = [new Paragraph({
    spacing: { before: 120, after: 0 },
    shading: { type: ShadingType.CLEAR, fill },
    border: { left: { style: BorderStyle.SINGLE, size: 18, color: bar },
              top: { style: BorderStyle.SINGLE, size: 2, color: fill },
              bottom: { style: BorderStyle.SINGLE, size: 2, color: fill } },
    indent: { left: 160, right: 160 },
    children: [new TextRun({ text: title, bold: true, size: 20, color: DARK })],
  })];
  for (let i = 0; i < body.length; i++) {
    out.push(new Paragraph({
      spacing: { after: i === body.length - 1 ? 160 : 40 },
      shading: { type: ShadingType.CLEAR, fill },
      border: { left: { style: BorderStyle.SINGLE, size: 18, color: bar },
                top: { style: BorderStyle.SINGLE, size: 2, color: fill },
                bottom: { style: BorderStyle.SINGLE, size: 2, color: fill } },
      indent: { left: 160, right: 160 },
      children: [new TextRun({ text: body[i], size: 20, color: DARK })],
    }));
  }
  return out;
}
function Fig(file, caption, widthPx) {
  const buf = fs.readFileSync(file);
  const w = widthPx || 640;
  const dims = { 'fig1_auditor_overview.png': [1160, 700], 'fig2_live_connect.png': [1160, 600],
                 'fig3_step_through.png': [1160, 700], 'fig4_outputs.png': [1160, 512],
                 'fig5_architecture.png': [1160, 660], 'fig6_maintenance.png': [1160, 560],
                 'fig7_two_data_planes.png': [1160, 720] };
  const base = file.split('/').pop();
  const [ow, oh] = dims[base] || [1160, 700];
  const h = Math.round(w * oh / ow);
  return [
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 160, after: 60 },
      children: [new ImageRun({ data: buf, type: 'png', transformation: { width: w, height: h } })] }),
    new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 200 },
      children: [new TextRun({ text: caption, italics: true, size: 18, color: MUT })] }),
  ];
}
function Tbl(headers, rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  const cell = (text, opts) => new TableCell({
    width: { size: opts.w, type: WidthType.DXA },
    shading: opts.head ? { type: ShadingType.CLEAR, fill: HEADBG } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ spacing: { after: 0 },
      children: [new TextRun({ text: String(text), bold: opts.head, size: 18,
        font: opts.mono ? 'Consolas' : undefined, color: DARK })] })],
  });
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    borders: {
      top: { style: BorderStyle.SINGLE, size: 2, color: LINE },
      bottom: { style: BorderStyle.SINGLE, size: 2, color: LINE },
      left: { style: BorderStyle.SINGLE, size: 2, color: LINE },
      right: { style: BorderStyle.SINGLE, size: 2, color: LINE },
      insideHorizontal: { style: BorderStyle.SINGLE, size: 2, color: LINE },
      insideVertical: { style: BorderStyle.SINGLE, size: 2, color: LINE },
    },
    rows: [
      new TableRow({ tableHeader: true,
        children: headers.map((h, i) => cell(h, { head: true, w: widths[i] })) }),
      ...rows.map((r) => new TableRow({
        children: r.map((c, i) => cell(c, { w: widths[i] })) })),
    ],
  });
}
const NUMBERING = {
  config: [
    { reference: 'bul', levels: [
      { level: 0, format: LevelFormat.BULLET, text: '•', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 460, hanging: 240 } } } },
      { level: 1, format: LevelFormat.BULLET, text: '◦', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 820, hanging: 240 } } } } ] },
    { reference: 'num', levels: [
      { level: 0, format: LevelFormat.DECIMAL, text: '%1.', alignment: AlignmentType.LEFT,
        style: { paragraph: { indent: { left: 460, hanging: 240 } } } } ] },
  ],
};
function Bul(text, lvl) { return P(text, { numbering: { reference: 'bul', level: lvl || 0 }, spacing: { after: 70 } }); }
function BulRich(runs, lvl) { return Rich(runs, { numbering: { reference: 'bul', level: lvl || 0 }, spacing: { after: 70 } }); }
let numInst = 0;
function NumList(items) { numInst += 1; const inst = numInst;
  return items.map((t) => P(t, { numbering: { reference: 'num', level: 0, instance: inst }, spacing: { after: 70 } })); }

function pageSetup(titleShort) {
  return {
    properties: { page: { size: LETTER, margin: { top: 1080, bottom: 1080, left: 1080, right: 1080 } } },
    headers: { default: new Header({ children: [new Paragraph({
      alignment: AlignmentType.RIGHT, spacing: { after: 0 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: LINE } },
      children: [new TextRun({ text: titleShort, size: 16, color: MUT })] })] }) },
    footers: { default: new Footer({ children: [new Paragraph({
      alignment: AlignmentType.CENTER, spacing: { before: 60 },
      children: [new TextRun({ text: 'Page ', size: 16, color: MUT }),
                 new TextRun({ children: [PageNumber.CURRENT], size: 16, color: MUT }),
                 new TextRun({ text: ' of ', size: 16, color: MUT }),
                 new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 16, color: MUT })] })] }) },
  };
}
module.exports = { P, Rich, Code, Note, Fig, Tbl, Bul, BulRich, NumList, NUMBERING, pageSetup,
  LETTER, ACC, DARK, MUT, LINE, HEADBG };
