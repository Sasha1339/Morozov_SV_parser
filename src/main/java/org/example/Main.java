package org.example;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        final int[] flag = new int[1];
        flag[0] = 0;
        final int[] flag1 = new int[1];
        flag1[0] = 0;
        CalculateKZ calculateKZ = new CalculateKZ();
        EthernetListener ethernetListener = new EthernetListener();
        ethernetListener.setNicName(""); /*такую сетевую карту показал мне статический метод*/

        SVDecoder svDecoder = new SVDecoder();

        ethernetListener.addListener(packet -> {
            Optional<SVPacket> svPacket = svDecoder.decode(packet);
            if (svPacket.isPresent()){
               //System.out.println(svPacket.get().getDataset().getInstIa());
               calculateKZ.findMaxValue(svPacket.get());
               if (flag[0] != calculateKZ.getArrayKZ().size()){
                   System.out.println(calculateKZ.getArrayKZ().get(flag[0]));
                   flag[0] += 1;
                   if (flag1[0] == 0){
                       System.out.println(calculateKZ.getInformationNormal());
                       flag1[0] = 1;
                   }

               }

            }



        });

        /*После запуска с помощью приложения, которое создает фальшивые пакеты и отправляет их
        * на ту карту которую мы указали в сеттере, увидим набор чисел и букв*/
        ethernetListener.start();
        /*Пакеты то мы получили, а теперь надо все преобразовать в человеческий вид
        * для этого создадим контейнер SVPacket*/
        //System.out.println(calculateKZ);

    }
}