# FIT-BIT-IPK-2020-proj2

Druhý projekt do předmětu Počítačové komunikace a sítě na FIT VUT v Brně 2020

## Implementace

Tento projekt je implementován v jazyce C++11 a pro filtrování a zachytávání paketů je použita knihovna libpcap.
Při zadání více argumentů `-p port` nebo `--port port` lze zachytávat síťový provoz na více portech.

## Sestavení a spuštění

Pro sestavení prokjektu je použita utilita `make`.

```shell
make
```

Program musí být spuštěn s právy uživatele `root` nebo uživatel musí mít povolené capability bity `CAP_NET_RAW` a `CAP_NET_ADMIN`.

Zobrazení dostupných síťových rozhraní:
```shell
sudo ./ipk-sniffer
```

Zachycení 5 paketů na síťovém rozhraní `eno1` na TCP portu `80`:

```shell
sudo ./ipk-sniffer -i eno1 -p 80 -t -n 5
```

