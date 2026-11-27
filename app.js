const alerts = [
  {name:'Brute force attempt',icon:'⌑',level:'high',ip:'185.220.101.47',model:'Anomaly detection',time:'2 min ago'},
  {name:'Port scan detected',icon:'⌁',level:'medium',ip:'103.45.67.12',model:'Intrusion predictor',time:'18 min ago'},
  {name:'Suspicious DNS query',icon:'⌘',level:'medium',ip:'91.240.118.33',model:'Malware classifier',time:'34 min ago'},
  {name:'Unusual data transfer',icon:'⇧',level:'low',ip:'172.16.24.108',model:'Anomaly detection',time:'1 hr ago'},
  {name:'Repeated login failures',icon:'⌑',level:'high',ip:'45.155.205.22',model:'Anomaly detection',time:'2 hr ago'},
  {name:'Known botnet signature',icon:'⌘',level:'medium',ip:'194.26.29.101',model:'Malware classifier',time:'3 hr ago'}
];
let showingAll = false;
const tbody = document.getElementById('alertRows');
const toast = document.getElementById('toast');
function renderAlerts(){
  const visible = showingAll ? alerts : alerts.slice(0,4);
  tbody.innerHTML = visible.map(a => `<tr><td><div class="threat-name"><span class="threat-icon ${a.level}">${a.icon}</span>${a.name}</div></td><td class="ip">${a.ip}</td><td>${a.model}</td><td><span class="severity ${a.level}"><i></i>${a.level[0].toUpperCase()+a.level.slice(1)}</span></td><td>${a.time}</td><td><button class="row-more" aria-label="More options for ${a.name}" title="Alert details" data-threat="${a.name}">···</button></td></tr>`).join('');
  document.getElementById('showingCount').textContent = visible.length;
  document.getElementById('loadMore').innerHTML = showingAll ? 'Show fewer <span>↑</span>' : 'View all threats <span>→</span>';
  document.getElementById('alertCount').textContent = alerts.length;
  document.getElementById('navAlertCount').textContent = alerts.length;
}
function showToast(message){toast.textContent=message;toast.classList.add('show');clearTimeout(showToast.timer);showToast.timer=setTimeout(()=>toast.classList.remove('show'),2600)}
renderAlerts();
document.getElementById('loadMore').addEventListener('click',()=>{showingAll=!showingAll;renderAlerts()});
document.getElementById('viewAll').addEventListener('click',()=>{showingAll=true;renderAlerts();document.getElementById('alerts').scrollIntoView({behavior:'smooth'})});
document.getElementById('themeToggle').addEventListener('click',()=>document.body.classList.toggle('dark'));
document.getElementById('rangeButton').addEventListener('click',()=>showToast('Showing the last 24 hours of sample activity.'));
document.getElementById('modelDetails').addEventListener('click',()=>showToast('All three detection models are active and healthy.'));
tbody.addEventListener('click',e=>{const button=e.target.closest('[data-threat]');if(button)showToast(`${button.dataset.threat} · Alert details`)});

