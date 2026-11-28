#!/usr/bin/env python
# coding: utf-8

# In[1]:


import glob, json, re
import pandas as pd
import matplotlib.pyplot as plt

rows = []
for f in sorted(glob.glob("../logs-reels/raw/cowrie.json*")):
    for l in open(f):
        if l.strip():
            rows.append(json.loads(l))
cw = pd.DataFrame(rows)
cw["timestamp"] = pd.to_datetime(cw["timestamp"], utc=True)
cw = cw.drop_duplicates(subset=["session", "eventid", "timestamp"])
print(cw.shape, cw["timestamp"].min(), cw["timestamp"].max())
cw["eventid"].value_counts()


# In[2]:


oc_rows = []
for l in open("../logs-reels/raw/opencanary.log"):
    if not l.strip(): continue
    d = json.loads(l)
    if d["logtype"] == 1001: continue
    oc_rows.append({"timestamp": pd.to_datetime(d["utc_time"], utc=True),
                    "src_ip": d["src_host"], "dst_port": d["dst_port"],
                    "logtype": d["logtype"],
                    "username": d["logdata"].get("USERNAME"),
                    "password": d["logdata"].get("PASSWORD")})
oc = pd.DataFrame(oc_rows)
oc["service"] = oc["dst_port"].map({21:"FTP", 80:"HTTP", 3306:"MySQL"}).fillna("autre")
oc.groupby(["src_ip", "service"]).size()


# In[3]:


sondes = cw[(cw["eventid"] == "cowrie.login.failed") &
            (cw["username"].str.contains(r"HTTP/|sip:|SIP/|^Call-ID|^Via:|^CSeq", na=False) |
             cw["password"].str.contains(r"HTTP/|sip:|SIP/|^Call-ID|^Via:|^CSeq", na=False))]
print(len(sondes), "événements ressemblant à des sondes de scan")
sondes[["src_ip", "dst_port", "username"]].head(10)


# In[4]:


motif = r"HTTP/|sip:|SIP/|^Call-ID|^Via:|^CSeq|^Contact:|^From:|^To:|^Max-Forwards|^Accept:|^Content-Length"
est_sonde = (cw["username"].fillna("").str.contains(motif) |
             cw["password"].fillna("").str.contains(motif))

tent = cw[cw["eventid"].isin(["cowrie.login.failed", "cowrie.login.success"])].copy()
tent["sonde"] = est_sonde.loc[tent.index]
vraies = tent[~tent["sonde"]]

print("Tentatives totales :", len(tent))
print("Sondes de scan     :", tent["sonde"].sum())
print("Vraies tentatives  :", len(vraies))
print("  échecs :", (vraies["eventid"] == "cowrie.login.failed").sum())
print("  succès :", (vraies["eventid"] == "cowrie.login.success").sum())


# In[5]:


print("Top utilisateurs :\n", vraies["username"].value_counts().head(10), "\n")
print("Top mots de passe :\n", vraies["password"].value_counts().head(10), "\n")
print("Top couples :\n", (vraies["username"] + ":" + vraies["password"]).value_counts().head(10))

top = vraies["password"].replace("", "(vide)").value_counts().head(10)
plt.figure(figsize=(8, 4))
top.plot(kind="barh"); plt.gca().invert_yaxis()
plt.title("Top mots de passe testés (sondes exclues)")
plt.xlabel("Tentatives"); plt.tight_layout()
plt.savefig("../graphiques/top-mots-de-passe-reel.png", dpi=150)
plt.show()


# In[6]:


vraies = vraies.assign(jour=vraies["timestamp"].dt.date, heure=vraies["timestamp"].dt.hour)

print(vraies.groupby("src_ip").size().sort_values(ascending=False), "\n")
print(vraies.groupby(["protocol"]).size(), "\n")
print(vraies.groupby("jour").size())

vraies.groupby("jour").size().plot(kind="bar", figsize=(8, 4), title="Tentatives par jour")
plt.ylabel("Tentatives"); plt.tight_layout()
plt.savefig("../graphiques/tentatives-par-jour.png", dpi=150); plt.show()


# In[7]:


profil = (cw.groupby("src_ip")
            .agg(sessions=("session", "nunique"),
                 echecs=("eventid", lambda s: (s == "cowrie.login.failed").sum()),
                 succes=("eventid", lambda s: (s == "cowrie.login.success").sum()),
                 commandes=("eventid", lambda s: (s == "cowrie.command.input").sum()),
                 premier=("timestamp", "min"), dernier=("timestamp", "max"))
            .sort_values("sessions", ascending=False))
profil


# In[8]:


regles = [
    (r"\buname\b|/proc/cpuinfo|\blscpu\b|\bhostname\b|/etc/os-release", "Reconnaissance système",   "T1082"),
    (r"\bwhoami\b|(^|[;&| ])(id|who|w|users)(\s|$)", "Découverte utilisateur", "T1033"),
    (r"/etc/passwd|/etc/shadow|\bcat /etc/",                            "Découverte de comptes",    "T1087.001"),
    (r"\bps\b|\btop\b",                                                 "Découverte de processus",  "T1057"),
    (r"wget|curl|tftp|ftpget",                                          "Téléchargement de charge", "T1105"),
    (r"chmod \+x|(^|[;&| ])\./\S|(^|[;&| ])(ba)?sh\s", "Exécution de script", "T1059.004"),
    (r"crontab|authorized_keys|\.ssh",                                  "Persistance",              "T1053 / T1098"),
    (r"rm -rf|history -c|unset HISTFILE",                               "Effacement de traces",     "T1070"),
    (r"xmrig|minerd|stratum|cpuminer",                                  "Minage de crypto",         "T1496"),
]
def classer(c): return [(i, t) for m, i, t in regles if re.search(m, c)]

cmds = cw[cw["eventid"] == "cowrie.command.input"].copy()
cmds["classification"] = cmds["input"].apply(classer)

print("NON CLASSÉES :")
print(cmds[cmds["classification"].str.len() == 0]["input"].value_counts())

detail = cmds.explode("classification").dropna(subset=["classification"])
detail["intention"] = detail["classification"].str[0]
detail["technique"] = detail["classification"].str[1]
synthese = (detail.groupby(["intention", "technique"]).size()
            .reset_index(name="occurrences").sort_values("occurrences", ascending=False))
synthese


# In[9]:


dl = cw[cw["eventid"] == "cowrie.session.file_download"][["timestamp", "src_ip", "url", "shasum"]]
print(dl.to_string())
print("\nHash uniques :", dl["shasum"].nunique())


# In[10]:


synthese.to_csv("../preuves/synthese-mitre-reel.csv", index=False)
detail[["session","src_ip","timestamp","input","intention","technique"]].to_csv(
    "../preuves/commandes-classees-reel.csv", index=False)
profil.to_csv("../preuves/profil-ip-reel.csv")
vraies[["timestamp","src_ip","protocol","dst_port","username","password","eventid"]].to_csv(
    "../preuves/tentatives-reel.csv", index=False)
sondes_df = tent[tent["sonde"]][["timestamp","src_ip","dst_port","username"]]
sondes_df.to_csv("../preuves/sondes-nmap-reel.csv", index=False)


# In[11]:


def machine(ip, jour):
    if ip == "192.168.56.1": return "PC Windows d'Alae (host-only)"
    if ip == "172.20.10.6":  return "Honeypot (auto-test)"
    if ip == "172.20.10.3":  return "PC Windows d'Alae"
    if ip == "172.20.10.5":  return "Kali (attaquant)"
    if ip == "172.20.10.2":  return "Kali (attaquant)" if jour <= "2026-11-20" else "PC Windows d'Alae"
    return "inconnu"

cw["jour"] = cw["timestamp"].dt.date.astype(str)
cw["machine"] = [machine(i, j) for i, j in zip(cw["src_ip"], cw["jour"])]

sess = cw[cw["eventid"] == "cowrie.session.connect"]
tab_machines = sess.groupby(["machine", "src_ip", "jour", "protocol"]).size().reset_index(name="sessions")
tab_machines.to_csv("../preuves/machines-reel.csv", index=False)
tab_machines


# In[12]:


norm = pd.read_csv("../logs-reels/logs_normalises_final.csv")
norm["timestamp"] = pd.to_datetime(norm["timestamp"], format="mixed", utc=True)

print("Normalisé :", len(norm), "lignes")
print(norm["service"].value_counts())
print("\nCowrie brut (connexions + commandes) :",
      cw["eventid"].isin(["cowrie.login.failed", "cowrie.login.success", "cowrie.command.input"]).sum())
print("Cowrie normalisé (ssh + telnet)      :", norm["service"].isin(["ssh", "telnet"]).sum())

