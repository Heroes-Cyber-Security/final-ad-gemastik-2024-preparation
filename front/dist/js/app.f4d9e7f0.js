(function(t){function e(e){for(var a,r,i=e[0],u=e[1],c=e[2],d=0,l=[];d<i.length;d++)r=i[d],Object.prototype.hasOwnProperty.call(o,r)&&o[r]&&l.push(o[r][0]),o[r]=0;for(a in u)Object.prototype.hasOwnProperty.call(u,a)&&(t[a]=u[a]);f&&f(e);while(l.length)l.shift()();return s.push.apply(s,c||[]),n()}function n(){for(var t,e=0;e<s.length;e++){for(var n=s[e],a=!0,r=1;r<n.length;r++){var i=n[r];0!==o[i]&&(a=!1)}a&&(s.splice(e--,1),t=u(u.s=n[0]))}return t}var a={},r={app:0},o={app:0},s=[];function i(t){return u.p+"js/"+({admin:"admin",main:"main"}[t]||t)+"."+{admin:"8c6436ac",main:"7287f3c7"}[t]+".js"}function u(e){if(a[e])return a[e].exports;var n=a[e]={i:e,l:!1,exports:{}};return t[e].call(n.exports,n,n.exports,u),n.l=!0,n.exports}u.e=function(t){var e=[],n={admin:1,main:1};r[t]?e.push(r[t]):0!==r[t]&&n[t]&&e.push(r[t]=new Promise((function(e,n){for(var a="css/"+({admin:"admin",main:"main"}[t]||t)+"."+{admin:"ba614488",main:"4fcc7dda"}[t]+".css",o=u.p+a,s=document.getElementsByTagName("link"),i=0;i<s.length;i++){var c=s[i],d=c.getAttribute("data-href")||c.getAttribute("href");if("stylesheet"===c.rel&&(d===a||d===o))return e()}var l=document.getElementsByTagName("style");for(i=0;i<l.length;i++){c=l[i],d=c.getAttribute("data-href");if(d===a||d===o)return e()}var f=document.createElement("link");f.rel="stylesheet",f.type="text/css",f.onload=e,f.onerror=function(e){var a=e&&e.target&&e.target.src||o,s=new Error("Loading CSS chunk "+t+" failed.\n("+a+")");s.code="CSS_CHUNK_LOAD_FAILED",s.request=a,delete r[t],f.parentNode.removeChild(f),n(s)},f.href=o;var m=document.getElementsByTagName("head")[0];m.appendChild(f)})).then((function(){r[t]=0})));var a=o[t];if(0!==a)if(a)e.push(a[2]);else{var s=new Promise((function(e,n){a=o[t]=[e,n]}));e.push(a[2]=s);var c,d=document.createElement("script");d.charset="utf-8",d.timeout=120,u.nc&&d.setAttribute("nonce",u.nc),d.src=i(t);var l=new Error;c=function(e){d.onerror=d.onload=null,clearTimeout(f);var n=o[t];if(0!==n){if(n){var a=e&&("load"===e.type?"missing":e.type),r=e&&e.target&&e.target.src;l.message="Loading chunk "+t+" failed.\n("+a+": "+r+")",l.name="ChunkLoadError",l.type=a,l.request=r,n[1](l)}o[t]=void 0}};var f=setTimeout((function(){c({type:"timeout",target:d})}),12e4);d.onerror=d.onload=c,document.head.appendChild(d)}return Promise.all(e)},u.m=t,u.c=a,u.d=function(t,e,n){u.o(t,e)||Object.defineProperty(t,e,{enumerable:!0,get:n})},u.r=function(t){"undefined"!==typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(t,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(t,"__esModule",{value:!0})},u.t=function(t,e){if(1&e&&(t=u(t)),8&e)return t;if(4&e&&"object"===typeof t&&t&&t.__esModule)return t;var n=Object.create(null);if(u.r(n),Object.defineProperty(n,"default",{enumerable:!0,value:t}),2&e&&"string"!=typeof t)for(var a in t)u.d(n,a,function(e){return t[e]}.bind(null,a));return n},u.n=function(t){var e=t&&t.__esModule?function(){return t["default"]}:function(){return t};return u.d(e,"a",e),e},u.o=function(t,e){return Object.prototype.hasOwnProperty.call(t,e)},u.p="/",u.oe=function(t){throw console.error(t),t};var c=window["webpackJsonp"]=window["webpackJsonp"]||[],d=c.push.bind(c);c.push=e,c=c.slice();for(var l=0;l<c.length;l++)e(c[l]);var f=d;s.push([0,"chunk-vendors"]),n()})({0:function(t,e,n){t.exports=n("56d7")},1953:function(t,e,n){},"56d7":function(t,e,n){"use strict";n.r(e);n("e260"),n("e6cf"),n("cca6"),n("a79d");var a=n("2b0e"),r=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n(t.layout,{tag:"component"},[n("router-view")],1)},o=[],s={computed:{layout:function(){return this.$route.meta.layout||"default-layout"}}},i=s,u=(n("5c0b"),n("2877")),c=Object(u["a"])(i,r,o,!1,null,null,null),d=c.exports,l=n("1da1"),f=(n("96cf"),n("d3b7"),n("3ca3"),n("ddb0"),n("8c4f")),m=n("f121"),h=function(){return n.e("main").then(n.bind(null,"3cb4"))},p=function(){return n.e("main").then(n.bind(null,"ddee"))},v=function(){return n.e("main").then(n.bind(null,"4dbc"))},b=function(){return n.e("admin").then(n.bind(null,"23b1"))},g=function(){return n.e("admin").then(n.bind(null,"f225"))},k=function(){return n.e("admin").then(n.bind(null,"b022"))},y=function(){return n.e("admin").then(n.bind(null,"e38e"))},_=function(){return n.e("admin").then(n.bind(null,"a4ee"))};a["a"].use(f["a"]);var w=[{path:"/",name:"index",component:h},{path:"/live/",name:"live",component:p,meta:{layout:"empty-layout"}},{path:"/team/:id/",name:"team",component:v},{path:"/admin/login/",name:"adminLogin",component:b},{path:"/admin/",name:"admin",component:g,meta:{auth:!0}},{path:"/admin/task/:id/",name:"taskAdmin",component:k,meta:{auth:!0}},{path:"/admin/team/:id/",name:"teamAdmin",component:y,meta:{auth:!0}},{path:"/admin/create_task/",name:"createTask",component:k,meta:{auth:!0}},{path:"/admin/create_team/",name:"createTeam",component:y,meta:{auth:!0}},{path:"/admin/teamtask_log/team/:teamId/task/:taskId/",name:"adminTeamTaskLog",component:_,meta:{auth:!0}}],T=new f["a"]({mode:"history",base:"/",routes:w});T.beforeEach(function(){var t=Object(l["a"])(regeneratorRuntime.mark((function t(e,n,a){var r;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:if(!e.meta.auth){t.next=14;break}return r=!1,t.prev=2,t.next=5,T.$http.get("".concat(m["d"],"/api/admin/status/"));case 5:r=!0,t.next=11;break;case 8:t.prev=8,t.t0=t["catch"](2),a({name:"adminLogin"});case 11:r&&a(),t.next=15;break;case 14:a();case 15:case"end":return t.stop()}}),t,null,[[2,8]])})));return function(e,n,a){return t.apply(this,arguments)}}());var O=T,j=n("bc3a"),P=n.n(j),S=n("5530"),x=(n("4160"),n("159b"),n("4e82"),n("0d03"),n("d81d"),n("2f62")),R=n("0e44"),C=n("b85c"),E=n("d4ec"),$=n("bee2"),M=(n("b0c0"),n("4de4"),n("13d5"),n("caad"),n("2532"),n("de4d")),I=function(){function t(e){var n=e.name,a=e.ip,r=e.id,o=e.teamTasks,s=e.tasks,i=e.highlighted;Object(E["a"])(this,t),this.name=n,this.ip=a,this.id=r,this.highlighted=i,this.taskModels=s,this.update(o)}return Object($["a"])(t,[{key:"update",value:function(t){var e=this;this.tasks=t.filter((function(t){var n=t.teamId;return n===e.id})),this.score=this.tasks.reduce((function(t,e){var n=e.score,a=e.sla;return t+n*(a/100)}),0);var n,a=this.tasks.map((function(t){return t.taskId})),r=Object(C["a"])(this.taskModels);try{for(r.s();!(n=r.n()).done;){var o=n.value;a.includes(o.id)||this.tasks.push(new M["a"]({id:0,task_id:o.id,team_id:this.id,status:0,stolen:0,lost:0,score:0,checks:0,checks_passed:0}))}}catch(s){r.e(s)}finally{r.f()}this.tasks.sort(M["a"].comp)}}],[{key:"comp",value:function(t,e){return e.score-t.score}}]),t}(),L=I,A=n("f1a4");a["a"].use(x["a"]);var N=new x["a"].Store({plugins:[Object(R["a"])({paths:["showPonies"]})],state:{round:0,roundTime:null,roundStart:null,roundProgress:null,teams:null,tasks:null,teamTasks:null,showPonies:!0,layout:"default-layout"},mutations:{setRound:function(t,e){t.round=e},setRoundStart:function(t,e){t.roundStart=e},setRoundTime:function(t,e){t.roundTime=e},setRoundProgress:function(t,e){t.roundProgress=e},setTeams:function(t,e){t.teams=e},setTasks:function(t,e){t.tasks=e},setGameState:function(t,e){t.round=e.round,t.roundStart=e.roundStart,t.teamTasks=e.teamTasks},updateTeams:function(t){null!==t.teams&&(t.teams.forEach((function(e){e.update(t.teamTasks)})),t.teams=t.teams.sort(L.comp))},togglePonies:function(t){t.showPonies=!t.showPonies},setLayout:function(t,e){t.layout=e}},getters:{layout:function(t){return t.layout}},actions:{fetchRoundTime:function(){var t=Object(l["a"])(regeneratorRuntime.mark((function t(e){var n,a;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return t.next=2,this.$http.get("/client/config/");case 2:n=t.sent,a=n.data.round_time,e.commit("setRoundTime",a);case 5:case"end":return t.stop()}}),t,this)})));function e(e){return t.apply(this,arguments)}return e}(),calculateRoundProgress:function(t){var e=t.state,n=e.round,a=e.roundTime,r=e.roundStart;(null===a||null===r||n<1)&&t.commit("setRoundProgress",null);var o=((new Date).getTime()/1e3-r-a)/a;o=Math.min(o,1),o=Math.floor(100*o),t.commit("setRoundProgress",o)},handleUpdateScoreboardMessage:function(t,e){var n=e.round,a=e.round_start,r=e.team_tasks;r=r.map((function(t){return new M["a"](t)}));var o={round:n,roundStart:a,teamTasks:r};t.commit("setGameState",o),t.commit("updateTeams")},handleInitScoreboardMessage:function(t,e){var n=e.state,a=e.teams,r=e.tasks;r=r.map((function(t){return new A["a"](t)})).sort(A["a"].comp),t.commit("setTasks",r),t.dispatch("handleUpdateScoreboardMessage",n),a=a.map((function(e){return new L(Object(S["a"])({teamTasks:t.state.teamTasks,tasks:t.state.tasks},e))})).sort(L.comp),t.commit("setTeams",a)}}}),U=N,D=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{attrs:{id:"app"}},[n("header",[n("topbar")],1),n("container",[t._t("default")],2),t._m(0)],1)},B=[function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("footer",{staticClass:"footer"},[t._v(" Powered by "),n("span",{staticClass:"team"},[t._v("C4T BuT S4D")]),t._v(" CTF team ")])}],F=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"container"},[t._t("default")],2)},K=[],q=(n("e5a0"),{}),G=Object(u["a"])(q,F,K,!1,null,"831e0c14",null),H=G.exports,J=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{staticClass:"topbar"},[n("router-link",{staticClass:"tp",attrs:{to:"/live/"}},[t._v("Live")]),n("div",{staticClass:"progress-bar",style:{width:t.roundProgress+"%"}}),n("div",{staticClass:"tp"},[t._v("Round: "+t._s(t.round))])],1)},W=[],z=(n("4795"),{data:function(){return{timer:null}},created:function(){var t=Object(l["a"])(regeneratorRuntime.mark((function t(){var e=this;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return t.next=2,this.$store.dispatch("fetchRoundTime");case 2:this.timer=setInterval((function(){return e.$store.dispatch("calculateRoundProgress")}),500);case 3:case"end":return t.stop()}}),t,this)})));function e(){return t.apply(this,arguments)}return e}(),beforeRouteLeave:function(t,e,n){clearInterval(this.timer),n()},computed:Object(x["b"])(["round","roundProgress"])}),Q=z,V=(n("ec27"),Object(u["a"])(Q,J,W,!1,null,"14c1d177",null)),X=V.exports,Y=n("8e27"),Z=n.n(Y),tt={components:{Container:H,Topbar:X},data:function(){return{server:null}},created:function(){var t=Object(l["a"])(regeneratorRuntime.mark((function t(){var e=this;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:this.server=Z()("".concat(m["d"],"/game_events"),{forceNew:!0}),this.server.on("connect_error",(function(){e.error="Can't connect to server"})),this.server.on("init_scoreboard",(function(t){var n=t.data;e.error=null,e.$store.dispatch("handleInitScoreboardMessage",n)})),this.server.on("update_scoreboard",(function(t){var n=t.data;e.error=null,e.$store.dispatch("handleUpdateScoreboardMessage",n)}));case 4:case"end":return t.stop()}}),t,this)})));function e(){return t.apply(this,arguments)}return e}()},et=tt,nt=(n("d16c"),Object(u["a"])(et,D,B,!1,null,"4f40b6be",null)),at=nt.exports,rt=function(){var t=this,e=t.$createElement,n=t._self._c||e;return n("div",{attrs:{id:"app"}},[t._t("default")],2)},ot=[],st=(n("ea97"),{}),it=Object(u["a"])(st,rt,ot,!1,null,null,null),ut=it.exports;a["a"].config.productionTip=!1,P.a.defaults.baseURL=m["a"],P.a.defaults.withCredentials=!0,a["a"].prototype.$http=P.a,O.$http=P.a,U.$http=P.a,a["a"].component("default-layout",at),a["a"].component("empty-layout",ut),new a["a"]({router:O,store:U,render:function(t){return t(d)}}).$mount("#app")},"5c0b":function(t,e,n){"use strict";n("9c0c")},"5dc6":function(t,e,n){},"9c0c":function(t,e,n){},b071:function(t,e,n){},d16c:function(t,e,n){"use strict";n("b071")},de4d:function(t,e,n){"use strict";var a=n("d4ec"),r=n("bee2"),o=function(){function t(e){var n=e.id,r=e.task_id,o=e.team_id,s=e.status,i=e.stolen,u=e.lost,c=e.score,d=e.checks,l=e.checks_passed,f=e.message;Object(a["a"])(this,t),this.id=n,this.taskId=r,this.teamId=o,this.status=s,this.stolen=i,this.lost=u,this.sla=100*l/Math.max(d,1),this.score=c,this.message=""===f&&101==this.status?"OK":f}return Object(r["a"])(t,null,[{key:"comp",value:function(t,e){return t.taskId-e.taskId}}]),t}();e["a"]=o},e5a0:function(t,e,n){"use strict";n("5dc6")},ea97:function(t,e,n){"use strict";n("ec79")},ec27:function(t,e,n){"use strict";n("1953")},ec79:function(t,e,n){},f121:function(t,e,n){"use strict";n.d(e,"d",(function(){return r})),n.d(e,"a",(function(){return o})),n.d(e,"g",(function(){return i})),n.d(e,"f",(function(){return s})),n.d(e,"h",(function(){return d})),n.d(e,"c",(function(){return l})),n.d(e,"e",(function(){return u})),n.d(e,"b",(function(){return c}));var a="";a=window.location.origin;var r=a,o="".concat(r,"/api"),s=[101,102,103,104,110],i={101:"UP",102:"CORRUPT",103:"MUMBLE",104:"DOWN",110:"CHECK FAILED","-1":"OFFLINE"},u={101:"#7dfc74",102:"#5191ff",103:"#ff9114",104:"#ff5b5b",110:"#ffff00","-1":"#fa83fc"},c="#ffffff",d=["#ffdf00","#c0c0c0","#d3983f"],l="#ffffff"},f1a4:function(t,e,n){"use strict";var a=n("d4ec"),r=n("bee2"),o=(n("b0c0"),function(){function t(e){var n=e.name,r=e.id;Object(a["a"])(this,t),this.name=n,this.id=r}return Object(r["a"])(t,null,[{key:"comp",value:function(t,e){return t.id-e.id}}]),t}());e["a"]=o}});
//# sourceMappingURL=app.f4d9e7f0.js.map