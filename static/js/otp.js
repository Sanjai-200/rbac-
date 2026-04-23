import { setTok, setUsr } from "./utils.js";
const raw = sessionStorage.getItem("otp_p");
if (!raw) { window.location.href="/"; }
const pend = JSON.parse(raw);
document.getElementById("otp-email").textContent = pend.email;

const inp    = document.getElementById("otpInput");
const verBtn = document.getElementById("verifyBtn");
const resBtn = document.getElementById("resendBtn");
const msgEl  = document.getElementById("msg");
const timerEl= document.getElementById("timer");
let cd=60, iv;

function startTimer(){
  clearInterval(iv);
  iv=setInterval(()=>{
    cd--;
    const m=String(Math.floor(cd/60)).padStart(2,"0");
    const s=String(cd%60).padStart(2,"0");
    timerEl.textContent=`${m}:${s}`;
    if(cd<=0){clearInterval(iv);msgEl.textContent="OTP expired. Click Resend.";verBtn.disabled=true;}
  },1000);
}
startTimer();

async function verifyOTP(){
  const entered=(inp.value||"").trim();
  if(!entered){msgEl.textContent="Enter OTP.";return;}
  verBtn.disabled=true; verBtn.textContent="Verifying..."; msgEl.textContent="";
  try{
    const r=await fetch("/api/verify-otp",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({user_id:pend.user_id, otp:entered})});
    const d=await r.json();
    if(!r.ok){msgEl.textContent=d.error||"Wrong OTP ❌";verBtn.disabled=false;verBtn.textContent="Verify OTP";return;}
    msgEl.textContent="OTP Verified ✅"; clearInterval(iv);
    // YOUR cleanup
    const email=pend.email;
    const lc=parseInt(localStorage.getItem(email+"_lc")||"0")+1;
    localStorage.setItem(email+"_lc",lc);
    sessionStorage.setItem(email+"_fa",0);
    localStorage.removeItem(email+"_pfa");
    sessionStorage.removeItem("otp_p");
    ["pd","pl","pt","plc","pfa2"].forEach(k=>sessionStorage.removeItem(k));
    setTok(d.token); setUsr({role:d.role,email:d.email,name:d.name});
    const map={super_admin:"/super-admin",admin:"/admin",user:"/user"};
    setTimeout(()=>window.location.href=map[d.role]||"/user",1000);
  }catch(e){msgEl.textContent="Error: "+e.message;verBtn.disabled=false;verBtn.textContent="Verify OTP";}
}

async function resendOTP(){
  const email=pend.email;
  if(!email){msgEl.textContent="Session lost. Login again.";setTimeout(()=>window.location.href="/",2000);return;}
  resBtn.textContent="Sending...";
  try{
    await fetch("/api/resend-otp",{method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify({user_id:pend.user_id,email})});
    msgEl.textContent="New OTP sent 📩";
  }catch{msgEl.textContent="Failed to resend. Try again.";}
  cd=60; startTimer(); resBtn.textContent="Resend OTP";
}

verBtn.addEventListener("click",verifyOTP);
resBtn.addEventListener("click",resendOTP);
