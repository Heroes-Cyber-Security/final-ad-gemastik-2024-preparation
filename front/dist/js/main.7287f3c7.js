(window["webpackJsonp"]=window["webpackJsonp"]||[]).push([["main"],{"07ac":function(t,e,s){var a=s("23e7"),n=s("6f53").values;a({target:"Object",stat:!0},{values:function(t){return n(t)}})},"0acf":function(t,e,s){"use strict";s("ed12")},"0b51":function(t,e,s){"use strict";s("bc02")},"0ebb":function(t,e,s){"use strict";s("dae0")},"3cb4":function(t,e,s){"use strict";s.r(e);var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",[s("statuses"),s("scoreboard")],1)},n=[],r=function(){var t=this,e=t.$createElement,s=t._self._c||e;return null!==t.teams?s("score-table",{attrs:{headRowTitle:"#",teamClickable:!0,tasks:t.tasks,teams:t.teams},on:{openTeam:t.openTeam}}):t._e()},i=[],c=s("3e4e"),o=s("2f62"),l={components:{ScoreTable:c["a"]},methods:{openTeam:function(t){this.$router.push({name:"team",params:{id:t}})["catch"]((function(){}))}},computed:Object(o["b"])(["teams","tasks"])},u=l,d=s("2877"),f=Object(d["a"])(u,r,i,!1,null,"9099b88e",null),m=f.exports,p=s("c1f1"),v={components:{Scoreboard:m,Statuses:p["a"]}},_=v,b=Object(d["a"])(_,a,n,!1,null,"7acd0b8a",null);e["default"]=b.exports},"3e4e":function(t,e,s){"use strict";var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",{staticClass:"table"},[s("div",{staticClass:"row"},[s("div",{staticClass:"number"},[t._v(t._s(t.headRowTitle))]),s("div",{staticClass:"team"},[t._v("team")]),s("div",{staticClass:"score"},[t._v("score")]),s("div",{staticClass:"service-name"},t._l(t.tasks,(function(e){var a=e.name,n=e.id;return s("div",{key:a,staticClass:"service-cell",style:t.taskStyle,on:{click:function(e){return t.$emit("openTask",n)}}},[t._v(" "+t._s(a)+" "),t.admin?s("button",{staticClass:"edit",on:{click:function(e){return t.$emit("openTaskAdmin",n)}}},[s("i",{staticClass:"fas fa-edit"})]):t._e()])})),0)]),s("transition-group",{attrs:{name:"teams-list"}},t._l(t.teams,(function(e,a){var n=e.name,r=e.score,i=e.tasks,c=e.ip,o=e.id,l=e.highlighted;return s("div",{key:n,staticClass:"row",class:[l?"highlighted":""],style:{backgroundColor:t.getTeamRowBackground(a)}},[s("div",{staticClass:"team-group",class:l?"":"pd-3"},[s("div",{staticClass:"number",style:{backgroundColor:t.getTeamRowBackground(a)}},[t._v(" "+t._s(a+1)+" ")]),s("div",{staticClass:"team team-row",style:[t.teamStyle,{backgroundColor:t.getTeamRowBackground(a)}],on:{click:function(e){return t.$emit("openTeam",o)}}},[s("div",{staticClass:"team-name"},[t._v(t._s(n))]),s("div",{staticClass:"ip"},[t._v(t._s(c))]),t.admin?s("button",{staticClass:"edit",on:{click:[function(e){return t.$emit("openTeamAdmin",o)},function(t){t.stopPropagation()}]}},[s("i",{staticClass:"fas fa-edit"})]):t._e()]),s("div",{staticClass:"score",style:{backgroundColor:t.getTeamRowBackground(a)}},[t._v(" "+t._s(r.toFixed(2))+" ")])]),s("div",{staticClass:"service"},t._l(i,(function(e){var a=e.id,n=e.teamId,r=e.taskId,c=e.sla,o=e.score,l=e.stolen,u=e.lost,d=e.message,f=e.status;return s("div",{key:a,staticClass:"service-cell",style:{fontSize:1-i.length/20+"em",backgroundColor:t.getTeamTaskBackground(f)}},[t.admin?s("button",{staticClass:"tt-edit",on:{click:function(e){return t.$emit("openTeamTaskHistory",n,r)}}},[s("i",{staticClass:"fas fa-edit"})]):t._e(),s("button",{staticClass:"info"},[s("i",{staticClass:"fas fa-info-circle"}),s("span",{staticClass:"tooltip"},[t._v(t._s(d))])]),s("div",{staticClass:"sla"},[s("strong",[t._v("SLA")]),t._v(" : "+t._s(c.toFixed(2))+"% ")]),s("div",{staticClass:"fp"},[s("strong",[t._v("FP")]),t._v(" : "+t._s(o.toFixed(2))+" ")]),s("div",{staticClass:"flags"},[s("i",{staticClass:"fas fa-flag"}),t._v(" +"+t._s(l)+"/-"+t._s(u)+" ")])])})),0)])})),0)],1)},n=[],r=s("bc8f"),i=(s("ab94"),{props:{headRowTitle:{type:String,default:"#"},tasks:{type:Array,required:!0},teams:{type:Array,required:!0},teamClickable:Boolean,taskClickable:Boolean,admin:Boolean},data:function(){return{getTeamRowBackground:r["a"],getTeamTaskBackground:r["b"]}},computed:{teamStyle:function(){return this.teamClickable?{cursor:"pointer"}:{}},taskStyle:function(){return this.taskClickable?{cursor:"pointer"}:{}}}}),c=i,o=(s("0ebb"),s("2877")),l=Object(o["a"])(c,a,n,!1,null,"359d0233",null);e["a"]=l.exports},"4dbc":function(t,e,s){"use strict";s.r(e);var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",[s("statuses"),s("team-scoreboard")],1)},n=[],r=s("c1f1"),i=function(){var t=this,e=t.$createElement,s=t._self._c||e;return null!==t.error?s("div",[t._v(" "+t._s(t.error)+" ")]):null!==t.team?s("div",{staticClass:"table"},[s("div",{staticClass:"row"},[s("div",{staticClass:"team"},[t._v("team")]),s("div",{staticClass:"score"},[t._v("score")]),s("div",{staticClass:"service-name"},t._l(t.tasks,(function(e){var a=e.name;return s("div",{key:a,staticClass:"service-cell"},[t._v(" "+t._s(a)+" ")])})),0)]),s("div",t._l(t.states,(function(e,a){return s("div",{key:a,staticClass:"row"},[s("div",{staticClass:"team"},[s("div",{staticClass:"team-name"},[t._v(t._s(t.team.name))]),s("div",{staticClass:"ip"},[t._v(t._s(t.team.ip))])]),s("div",{staticClass:"score"},[t._v(" "+t._s(e.score.toFixed(2))+" ")]),s("div",{staticClass:"service"},t._l(e.tasks,(function(e,a){var n=e.sla,r=e.score,i=e.stolen,c=e.lost,o=e.message,l=e.status;return s("div",{key:a,staticClass:"service-cell",style:{fontSize:1-t.tasks.length/20+"em",backgroundColor:t.getTeamTaskBackground(l)}},[s("button",{staticClass:"info"},[s("i",{staticClass:"fas fa-info-circle"}),s("span",{staticClass:"tooltip"},[t._v(" "+t._s(o)+" ")])]),s("div",{staticClass:"sla"},[s("strong",[t._v("SLA")]),t._v(": "+t._s(n.toFixed(2))+"% ")]),s("div",{staticClass:"fp"},[s("strong",[t._v("FP")]),t._v(": "+t._s(r.toFixed(2))+" ")]),s("div",{staticClass:"flags"},[s("i",{staticClass:"fas fa-flag"}),t._v(" +"+t._s(i)+"/-"+t._s(c)+" ")])])})),0)])})),0)]):t._e()},c=[],o=(s("277d"),s("6b75"));function l(t){if(Array.isArray(t))return Object(o["a"])(t)}s("a4d3"),s("e01a"),s("d3b7"),s("d28b"),s("3ca3"),s("ddb0"),s("a630");function u(t){if("undefined"!==typeof Symbol&&null!=t[Symbol.iterator]||null!=t["@@iterator"])return Array.from(t)}var d=s("06c5");function f(){throw new TypeError("Invalid attempt to spread non-iterable instance.\nIn order to be iterable, non-array objects must have a [Symbol.iterator]() method.")}function m(t){return l(t)||u(t)||Object(d["a"])(t)||f()}var p=s("b85c"),v=s("1da1"),_=(s("96cf"),s("4de4"),s("4e82"),s("d81d"),s("13d5"),s("a9e3"),s("fb6a"),s("c975"),s("07ac"),s("bc8f")),b=s("f1a4"),h=s("de4d"),k=(s("ab94"),{data:function(){return{error:null,team:null,teamId:null,tasks:null,round:0,by_task:[],getTeamTaskBackground:_["b"]}},created:function(){var t=Object(v["a"])(regeneratorRuntime.mark((function t(){var e,s,a,n,r,i,c,o,l,u,d,f,v,_=this;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return this.teamId=this.$route.params.id,t.prev=1,t.next=4,this.$http.get("/client/teams/");case 4:return e=t.sent,s=e.data,t.next=8,this.$http.get("/client/tasks/");case 8:return a=t.sent,n=a.data,t.next=12,this.$http.get("/client/teams/".concat(this.teamId,"/"));case 12:r=t.sent,i=r.data,this.team=s.filter((function(t){var e=t.id;return e==_.teamId}))[0],this.tasks=n.map((function(t){return new b["a"](t)})).sort(b["a"].comp),this.round=i.reduce((function(t,e){var s=e.round;return Math.max(t,s)}),0),this.$store.commit("setRound",this.round),i=i.map((function(t){return{id:Number(t.id),round:Number(t.round),task_id:Number(t.task_id),team_id:Number(t.team_id),status:t.status,stolen:t.stolen,lost:t.lost,score:Number(t.score),checks:Number(t.checks),checks_passed:Number(t.checks_passed),timestamp_secs:Number(t.timestamp.slice(0,t.timestamp.indexOf("-"))),timestamp_num:Number(t.timestamp.slice(t.timestamp.indexOf("-")+1)),message:t.message}})),i=i.sort((function(t,e){var s=t.timestamp_secs,a=t.timestamp_num,n=e.timestamp_secs,r=e.timestamp_num;return s===n?r-a:n-s})),i=i.map((function(t){return new h["a"](t)})),this.by_task={},c=Object(p["a"])(i);try{for(c.s();!(o=c.n()).done;)l=o.value,u=l.taskId-1,this.by_task[u]||(this.by_task[u]=[]),this.by_task[u].push(l)}catch(k){c.e(k)}finally{c.f()}for(this.by_task=Object.values(this.by_task),d=Math.min.apply(Math,m(this.by_task.map((function(t){return t.length})))),this.states=[],f=function(t){_.states.push({tasks:_.by_task.map((function(e){return e[t]})),score:_.by_task.map((function(e){return e[t]})).reduce((function(t,e){var s=e.score,a=e.sla;return t+s*a/100}),0)})},v=0;v<d;v+=1)f(v);t.next=34;break;case 31:t.prev=31,t.t0=t["catch"](1),this.error="Can't connect to server";case 34:case"end":return t.stop()}}),t,this,[[1,31]])})));function e(){return t.apply(this,arguments)}return e}()}),g=k,C=(s("0acf"),s("2877")),w=Object(C["a"])(g,i,c,!1,null,"5a76aa78",null),y=w.exports,x={components:{TeamScoreboard:y,Statuses:r["a"]}},T=x,N=Object(C["a"])(T,a,n,!1,null,"545267e8",null);e["default"]=N.exports},5899:function(t,e){t.exports="\t\n\v\f\r                　\u2028\u2029\ufeff"},"58a8":function(t,e,s){var a=s("1d80"),n=s("5899"),r="["+n+"]",i=RegExp("^"+r+r+"*"),c=RegExp(r+r+"*$"),o=function(t){return function(e){var s=String(a(e));return 1&t&&(s=s.replace(i,"")),2&t&&(s=s.replace(c,"")),s}};t.exports={start:o(1),end:o(2),trim:o(3)}},"662c":function(t,e,s){"use strict";s("dd29")},"6f53":function(t,e,s){var a=s("83ab"),n=s("df75"),r=s("fc6a"),i=s("d1e7").f,c=function(t){return function(e){var s,c=r(e),o=n(c),l=o.length,u=0,d=[];while(l>u)s=o[u++],a&&!i.call(c,s)||d.push(t?[s,c[s]]:c[s]);return d}};t.exports={entries:c(!0),values:c(!1)}},7156:function(t,e,s){var a=s("861d"),n=s("d2bb");t.exports=function(t,e,s){var r,i;return n&&"function"==typeof(r=e.constructor)&&r!==s&&a(i=r.prototype)&&i!==s.prototype&&n(t,i),t}},"79a6":function(t,e,s){"use strict";s("8c32")},"89ff":function(t,e,s){},"8ace":function(t,e,s){"use strict";var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",[null!==t.error?s("p",{staticClass:"error-message"},[t._v(t._s(t.error))]):t._t("default")],2)},n=[],r={props:{error:String}},i=r,c=(s("c8f0"),s("2877")),o=Object(c["a"])(i,a,n,!1,null,"7c304018",null);e["a"]=o.exports},"8c32":function(t,e,s){},a9e3:function(t,e,s){"use strict";var a=s("83ab"),n=s("da84"),r=s("94ca"),i=s("6eeb"),c=s("5135"),o=s("c6b6"),l=s("7156"),u=s("c04e"),d=s("d039"),f=s("7c73"),m=s("241c").f,p=s("06cf").f,v=s("9bf2").f,_=s("58a8").trim,b="Number",h=n[b],k=h.prototype,g=o(f(k))==b,C=function(t){var e,s,a,n,r,i,c,o,l=u(t,!1);if("string"==typeof l&&l.length>2)if(l=_(l),e=l.charCodeAt(0),43===e||45===e){if(s=l.charCodeAt(2),88===s||120===s)return NaN}else if(48===e){switch(l.charCodeAt(1)){case 66:case 98:a=2,n=49;break;case 79:case 111:a=8,n=55;break;default:return+l}for(r=l.slice(2),i=r.length,c=0;c<i;c++)if(o=r.charCodeAt(c),o<48||o>n)return NaN;return parseInt(r,a)}return+l};if(r(b,!h(" 0o1")||!h("0b1")||h("+0x1"))){for(var w,y=function(t){var e=arguments.length<1?0:t,s=this;return s instanceof y&&(g?d((function(){k.valueOf.call(s)})):o(s)!=b)?l(new h(C(e)),s,y):C(e)},x=a?m(h):"MAX_VALUE,MIN_VALUE,NaN,NEGATIVE_INFINITY,POSITIVE_INFINITY,EPSILON,isFinite,isInteger,isNaN,isSafeInteger,MAX_SAFE_INTEGER,MIN_SAFE_INTEGER,parseFloat,parseInt,isInteger,fromString,range".split(","),T=0;x.length>T;T++)c(h,w=x[T])&&!c(y,w)&&v(y,w,p(h,w));y.prototype=k,k.constructor=y,i(n,b,y)}},ab94:function(t,e,s){},bc02:function(t,e,s){},bc8f:function(t,e,s){"use strict";s.d(e,"a",(function(){return n})),s.d(e,"b",(function(){return r}));var a=s("f121");function n(t){return t<a["h"].length?a["h"][t]:a["c"]}function r(t){return a["e"][t]?a["e"][t]:a["b"]}},c1f1:function(t,e,s){"use strict";var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",{staticClass:"statuses"},t._l(t.statuses,(function(e){return s("div",{key:e,staticClass:"status-cell",style:{backgroundColor:t.getTeamTaskBackground(e)}},[t._v(" "+t._s(t.statusesNames[e])+" ")])})),0)},n=[],r=s("f121"),i=s("bc8f"),c={data:function(){return{statuses:r["f"],statusesNames:r["g"],getTeamTaskBackground:i["b"]}}},o=c,l=(s("662c"),s("2877")),u=Object(l["a"])(o,a,n,!1,null,"6e65e674",null);e["a"]=u.exports},c8f0:function(t,e,s){"use strict";s("89ff")},c975:function(t,e,s){"use strict";var a=s("23e7"),n=s("4d64").indexOf,r=s("a640"),i=[].indexOf,c=!!i&&1/[1].indexOf(1,-0)<0,o=r("indexOf");a({target:"Array",proto:!0,forced:c||!o},{indexOf:function(t){return c?i.apply(this,arguments)||0:n(this,t,arguments.length>1?arguments[1]:void 0)}})},dae0:function(t,e,s){},dd29:function(t,e,s){},ddee:function(t,e,s){"use strict";s.r(e);var a=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",{staticClass:"screen"},[s("button",{staticClass:"ponies-toggle-btn",on:{click:t.togglePonies}},[t._v(" Toggle ponies! ")]),t.showPonies?s("iframe",{staticClass:"pony",attrs:{src:"https://panzi.github.io/Browser-Ponies/ponies-iframe.html#fadeDuration=500&volume=1&fps=25&speed=3&audioEnabled=false&dontSpeak=true&showFps=false&showLoadProgress=false&speakProbability=0.1&spawn.masked%20matterhorn=1&spawn.nightmare%20moon=1&spawn.princess%20cadance=1&spawn.princess%20cadance%20(teenager)=1&spawn.princess%20celestia=1&spawn.princess%20celestia%20(alternate%20filly)=1&spawn.princess%20celestia%20(filly)=1&spawn.princess%20luna=1&spawn.princess%20luna%20(filly)=1&spawn.princess%20luna%20(season%201)=1&spawn.princess%20twilight%20sparkle=1&spawn.queen%20chrysalis=1&spawn.roseluck=1&spawn.sapphire%20shores=1&spawn.screw%20loose=1&spawn.screwball=1&spawn.seabreeze=1&spawn.sheriff%20silverstar=1&spawn.shoeshine=1&spawn.shopkeeper=1&spawn.silver%20spoon=1&spawn.sindy=1&spawn.sir%20colton%20vines=1&spawn.slendermane=1&spawn.soigne%20folio=1&spawn.stella=1&spawn.sue%20pie=1&spawn.suri%20polomare=1&spawn.twist=1&spawn.walter=1&spawnRandom=1&paddock=false&grass=false",width:"640",height:"480",frameborder:"0",scrolling:"no",marginheight:"0",marginwidth:"0",title:"pony"}}):t._e(),s("live-scoreboard")],1)},n=[],r=function(){var t=this,e=t.$createElement,s=t._self._c||e;return s("div",{staticClass:"flag"},[s("error-box",{attrs:{error:t.error}},t._l(t.events,(function(e,a){var n=e.attacker,r=e.victim,i=e.task,c=e.delta;return s("div",{key:a},[s("span",{staticClass:"mark"},[t._v(t._s(n))]),t._v(" stole a flag from "),s("span",{staticClass:"mark"},[t._v(t._s(r))]),t._v("'s service "),s("span",{staticClass:"mark"},[t._v(t._s(i))]),t._v(" and got "),s("span",{staticClass:"mark"},[t._v(t._s(c))]),t._v(" points ")])})),0)],1)},i=[],c=s("1da1"),o=(s("96cf"),s("b0c0"),s("4de4"),s("f121")),l=s("8e27"),u=s.n(l),d=s("8ace"),f={components:{ErrorBox:d["a"]},data:function(){return{error:null,server:null,teams:null,tasks:null,events:[]}},created:function(){var t=Object(c["a"])(regeneratorRuntime.mark((function t(){var e,s,a,n,r=this;return regeneratorRuntime.wrap((function(t){while(1)switch(t.prev=t.next){case 0:return t.prev=0,t.next=3,this.$http.get("".concat(o["d"],"/api/client/teams/"));case 3:return e=t.sent,s=e.data,t.next=7,this.$http.get("".concat(o["d"],"/api/client/tasks/"));case 7:a=t.sent,n=a.data,this.teams=s,this.tasks=n,t.next=17;break;case 13:return t.prev=13,t.t0=t["catch"](0),this.error="Can't connect to server",t.abrupt("return");case 17:this.server=u()("".concat(o["d"],"/live_events"),{forceNew:!0}),this.server.on("connect_error",(function(){r.error="Can't connect to server"})),this.server.on("flag_stolen",(function(t){var e=t.data;r.error=null;var s=e.attacker_id,a=e.victim_id,n=e.task_id,i=e.attacker_delta;r.events.unshift({attacker:r.teams.filter((function(t){var e=t.id;return e===s}))[0].name,victim:r.teams.filter((function(t){var e=t.id;return e===a}))[0].name,task:r.tasks.filter((function(t){var e=t.id;return e==n}))[0].name,delta:i})}));case 20:case"end":return t.stop()}}),t,this,[[0,13]])})));function e(){return t.apply(this,arguments)}return e}()},m=f,p=(s("0b51"),s("2877")),v=Object(p["a"])(m,r,i,!1,null,"6fd2ecae",null),_=v.exports,b=s("2f62"),h={components:{LiveScoreboard:_},methods:{togglePonies:function(){this.$store.commit("togglePonies")}},computed:Object(b["b"])(["showPonies"])},k=h,g=(s("79a6"),Object(p["a"])(k,a,n,!1,null,"7828c828",null));e["default"]=g.exports},ed12:function(t,e,s){}}]);
//# sourceMappingURL=main.7287f3c7.js.map