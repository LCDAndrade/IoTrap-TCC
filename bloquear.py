import json
import os
import time

LOG_PATH = "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
LOG_BLOQUEADOS = "ips_bloqueados.txt"
LIMITE_TENTATIVAS = 3

tentativas_por_ip = {}

print("[*] IoTrap - Monitor de Defesa Ativa Iniciado...")

with open(LOG_PATH, "r") as f:
    f.seek(0, os.SEEK_END)
    
    while True:
        linha = f.readline()
        if not linha:
            time.sleep(1)
            continue
            
        try:
            dados = json.loads(linha)
            if dados.get("eventid") == "cowrie.login.failed":
                ip = dados.get("src_ip")
                
                if ip:
                    tentativas_por_ip[ip] = tentativas_por_ip.get(ip, 0) + 1
                    print(f"[!] Tentativa falhada do IP: {ip} ({tentativas_por_ip[ip]}/{LIMITE_TENTATIVAS})")
                    
                    if tentativas_por_ip[ip] >= LIMITE_TENTATIVAS:
                        print(f"[+] LIMITE ATINGIDO! Bloqueando {ip} no iptables...")
                        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
                        
                        with open(LOG_BLOQUEADOS, "a") as log_file:
                            log_file.write(f"IP Bloqueado: {ip} - Tentativas: {tentativas_por_ip[ip]}\n")
                        
                        tentativas_por_ip[ip] = -999999 
        except:
            continue
