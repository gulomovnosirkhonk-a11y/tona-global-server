import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
const source=fs.readFileSync(new URL('./i18n.js',import.meta.url),'utf8');
const languages=['uz','en','ru','tr','kk','ar','zh-CN','hi','es','fr'];
for(const language of languages){
 const storage=new Map([['tona_language',language]]);let reloads=0;
 const context=vm.createContext({navigator:{language:'en-US'},document:{documentElement:{}},localStorage:{getItem:k=>storage.get(k),setItem:(k,v)=>storage.set(k,v)},location:{reload:()=>reloads++}});
 vm.runInContext(source,context);
 const data=vm.runInContext('({language:I18n.language,locale:I18n.locale,html:I18n.picker(),nav:I18n.t("Asosiy"),translations:TONA_TRANSLATIONS})',context);
 assert.equal(data.language,language);assert.equal(context.document.documentElement.dir,language==='ar'?'rtl':'ltr');
 assert.equal((data.html.match(/<option /g)||[]).length,10);assert.ok(data.nav.trim());
 const keys=Object.keys(data.translations.en);
 for(const [code,dict] of Object.entries(data.translations))for(const key of keys)assert.ok(typeof dict[key]==='string'&&dict[key].trim(),`${code}: ${key}`);
 vm.runInContext('I18n.choose("invalid")',context);assert.equal(reloads,0);
 vm.runInContext('I18n.choose("uz")',context);assert.equal(reloads,1);assert.equal(storage.get('tona_language'),'uz');
}
console.log('10 locales: complete dictionaries, persisted selection, safe invalid selection and Arabic RTL passed.');
