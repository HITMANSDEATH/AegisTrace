let cy = null, onSelect = () => {}, highlighted = null;
const lane = event => event.type === 'retrieval' ? 'context' : event.type.startsWith('tool_') ? 'tool' : 'state';
const colors = { paper:'#f5f5ef', green:'#2d503d', line:'#8c9d83', ink:'#263022', amber:'#936124', red:'#a33f32' };
export function initGraph(select) {
  onSelect = select;
  if (!window.cytoscape) return;
  cy = window.cytoscape({ container:document.getElementById('cy'), elements:[], minZoom:.15, maxZoom:2.8, wheelSensitivity:.18, boxSelectionEnabled:false,
    style:[
      { selector:'node', style:{ label:'data(label)', 'font-family':'IBM Plex Mono, monospace','font-size':11,'text-wrap':'wrap','text-max-width':109,'text-valign':'center','text-halign':'center',color:colors.ink,'background-color':'#e0e8d9','border-color':'#859878','border-width':1.1,width:136,height:53,shape:'roundrectangle','overlay-opacity':0 } },
      { selector:'.context',style:{'background-color':colors.paper,'border-color':'#9faa91',shape:'rectangle',height:46} },
      { selector:'.tool',style:{'background-color':'#e9deca','border-color':'#a7916e',shape:'diamond',width:157,height:85,'text-max-width':102,'font-size':10} },
      { selector:'.flagged',style:{'background-color':'#eee2c9','border-color':colors.amber,'border-style':'dashed','border-width':2} },
      { selector:'edge',style:{width:1.2,'line-color':colors.line,'target-arrow-color':colors.line,'target-arrow-shape':'triangle','arrow-scale':.65,'curve-style':'bezier','control-point-step-size':38,opacity:.72} },
      { selector:'.affected',style:{'border-color':colors.red,'border-style':'dashed',opacity:.45} },
      { selector:'edge.broken-link',style:{'line-color':colors.red,'target-arrow-color':colors.red,'line-style':'dashed',opacity:.4} },
      { selector:'.broken',style:{'background-color':'#f0dad3','border-color':colors.red,'border-width':2,color:'#802f26'} },
      { selector:'.selected',style:{'border-width':3,'border-color':colors.green,'underlay-color':'#96aa87','underlay-padding':6,'underlay-opacity':.18} },
      { selector:'.selected.broken',style:{'border-color':colors.red,'underlay-color':'#d79c8b'} },
      { selector:'edge.connected',style:{'line-color':colors.green,'target-arrow-color':colors.green,width:2,opacity:1} }
    ]
  });
  cy.on('tap','node', event => onSelect(event.target.id(),true));
  cy.on('mouseover','node', event => { document.getElementById('cy').style.cursor='pointer'; document.dispatchEvent(new CustomEvent('graph-hover',{detail:event.target.id()})); });
  cy.on('mouseout','node', () => { document.getElementById('cy').style.cursor='default'; document.dispatchEvent(new CustomEvent('graph-hover',{detail:null})); });
  new ResizeObserver(() => { cy.resize(); fitGraph(); }).observe(document.getElementById('cy'));
}
export function renderGraph(allEvents, position, verification, selected) {
  const events = allEvents.slice(0,position), visibleIds = new Set(events.map(event => event.id));
  const empty = document.getElementById('graph-empty'); empty.hidden = events.length > 0;
  if (!cy) {
    const fallback=document.getElementById('graph-fallback'); fallback.hidden=!events.length; fallback.replaceChildren();
    const note=document.createElement('p'); note.textContent='Graph library unavailable. Inspect the connected events below; verification still works.'; fallback.append(note);
    events.forEach(event => { const button=document.createElement('button');button.textContent=`${event.id} · ${event.label} ← ${event.parent_ids.join(', ') || 'start'}`;button.onclick=()=>onSelect(event.id,true);fallback.append(button); });
    return;
  }
  const counts = {context:0,state:0,tool:0}; const totals = {context:0,state:0,tool:0}; allEvents.forEach(event => totals[lane(event)]++);
  const max = Math.max(3,...Object.values(totals)); const width = (max-1)*185;
  const elements=[];
  events.forEach(event => {
    const tier=lane(event); const count=totals[tier]; const x=count>1 ? 90 + counts[tier]++ * width/(count-1) : 90 + width/2;
    const y=tier==='context' ? 90 : tier==='state' ? 240 : 360;
    const classes=[tier]; if(event.flagged) classes.push('flagged');
    if(event.directly_broken || verification?.firstBroken===event.seq) classes.push('broken'); else if(verification?.firstBroken && event.seq>verification.firstBroken) classes.push('affected');
    if(event.id===selected)classes.push('selected');
    elements.push({data:{id:event.id,label:`${event.id.toUpperCase()}\n${event.label}`},position:event.position||{x,y},classes:classes.join(' ')});
    event.parent_ids.forEach(parent => { if(visibleIds.has(parent)) elements.push({data:{id:`${parent}-${event.id}`,source:parent,target:event.id},classes:event.tampered?'broken-link':''}); });
  });
  cy.batch(()=>{cy.elements().remove();cy.add(elements);});
  cy.layout({name:'preset',fit:false}).run(); selectGraph(selected); fitGraph();
}
export function fitGraph() { if(cy?.nodes().length)cy.fit(undefined,32); }
export function zoomGraph(factor) { if(cy)cy.zoom({level:cy.zoom()*factor,renderedPosition:{x:cy.width()/2,y:cy.height()/2}}); }
export function selectGraph(id) { highlighted=id; if(!cy)return;cy.nodes().removeClass('selected');cy.edges().removeClass('connected');if(id){const node=cy.getElementById(id);node.addClass('selected');node.connectedEdges().addClass('connected');} }
