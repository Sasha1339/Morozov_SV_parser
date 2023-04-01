package org.example;

import lombok.Data;
import lombok.Setter;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

@Slf4j
public class EthernetListener {

    /*Класс который грабит пакеты из сетевой карты*/

    /*Данный метод статический и вызывется сам по себе, данный метод показывает какие
    * сетевые карты на данный момент находятся в рабочем состоянии, по этому методу можно
    * вписать нужную карту в сеттер*/
    static {


        try {
            for (PcapNetworkInterface nic : Pcaps.findAllDevs()) {
                log.info("Found NIC: {}", nic);
            }
        } catch (PcapNativeException e) {
            throw new RuntimeException(e);
        }

    }
    /*Зададим название сетевой карты*/
    @Setter
    private String nicName;
    /*При открытии сетевой карты, при добавлении ее в Джаву создается handle
    * По суте это обработчик этих сетевых карт*/
    private PcapHandle handle;
    private  final List<PacketListener> listeners = new CopyOnWriteArrayList<>();
    private final PacketListener defaultPacketListener = packet -> {
        /*System.out.println(packet);*/ //выведет пакеты то как они были отправлены
        listeners.forEach((listener -> listener.gotPacket(packet)));
    };




    /*Метод который запускает прием пакетов из сетевой карты*/
    @SneakyThrows
    public void start() {
        if (handle == null) {
            /*если карты нет, то обращается к методу инициализации и находит эту карту*/
            initializeNetworkInterface();
            if (handle != null) {
                /*Осуществим фильтрацию на низком уровне, вдруг что то другое придет, а нам это не нужно
                * нас интересуют только наши пакеты, также осуществляется в Pcap*/
                /*данным выражением сказали, что мы хотим получать только SV пакеты, соответсвенно пишем
                * 0х88ba, если бы мы хотели получать GOOSE пакеты тогда бы писали 0х88b8 */
                /*А еще указать что не просто все пакеты а еще и те у которых МАС-адрес назначения равен
                * 01:0C:CD:04:00:01*/
                String filter = "ether proto 0x88ba && ether dst 01:0C:CD:04:00:01";
                /*теперь мы должны на наш handle забиндить наш фильтер чтобы он применился*/
                handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
                /*Теперь нам нужно открывать перехват пакетов*/

                Thread captureThread = new Thread(()->{
                    /*Открываем закольцеванность ??? поток перехвата данных*/
                    /*1) 0 - без ограничей так написано в правилах
                    * 2) и должны передавать PackedListener то есть интерфейс
                    * в который нам Handle будет передавать наши сырые пакеты
                    * Он создан выше*/
                    try {
                        log.info("Starting packet capture");
                        handle.loop(0, defaultPacketListener);
                    } catch (PcapNativeException e) {
                        throw new RuntimeException(e);
                    } catch (InterruptedException e) {
                        throw new RuntimeException(e);
                    } catch (NotOpenException e) {
                        throw new RuntimeException(e);
                    }
                    log.info("Packet capture finished");
                });
                captureThread.start();


            }

        }
    }
    @SneakyThrows
    private void initializeNetworkInterface() {

        Optional<PcapNetworkInterface> nic = Pcaps.findAllDevs().stream()
                .filter(i -> nicName.equals(i.getDescription()))
                .findFirst();
        /*Если карта найдена, то мы должны открыть у нее handle*/
        if(nic.isPresent()) {
            /*открываем ее(карту) для работы, 1) задаем максимальный размер для пакетов который хотим ез
             * нее получать 1,5 Кб помоему,(больше 1500 при стандартных ситуациях быть не может
             * 2) - штука позволяет пропускать нашей сетевой карте в ситсему пакеты которые для нее не предназначались
             * Вспоминаем в пакетах ethernet содержит МАС-адресс назначения, и если не укакать
             * как второй пункт то ситсема увидит что МАС-адрес отличается от собственного МАС адреса
             * и не пропустит его, здесь мы говорим - пропускай все пакеты не зависимо от того какой был
             * МАС-адрес )3 задается тайм-аут - время ожидания 10 мс*/
            handle = nic.get().openLive(1500, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            log.info("Network handler created {}", nic);
        }else{
                log.error("Network interface is not found");
            }
        }

        public void addListener(PacketListener listener){
            listeners.add(listener);
        }

    }



