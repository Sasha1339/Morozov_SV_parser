package org.example;

import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.util.Optional;

@Slf4j
public class SVDecoder {
    /*По сути это парсер данных которые поступабт по сети в человеческий читабельный вид*/

    private static final int datasetSizeForFaseA = 64;
    private static final int datasetSizeForFaseB = 56;
    private static final int datasetSizeForFaseC = 48;
    private static final int datasetSizeForFaseNeutral = 40;
    private static  final int datasetForU = 32;
    private static final int datasetType = 12;//переводить не нужно, форма записи 0х88ba
    private static final int datasetAPPID = 14; //переводить не нужно, форма записи 0х4000
    private static final int datasetSvID = 33; //нужен перевод
    private static final int datasetSmpCnt = 77; //нужен перевод
    private static final int datasetСonfRef = 73;//нужен перевод
    private static final int datasetSmpSynch = 67;//нужен перевод

    public Optional<SVPacket> decode(PcapPacket packet){
        try{
            byte[] data = packet.getRawData();
            int length = data.length;

            SVPacket result = new SVPacket();

            result.setMacDst(byteArrayToMac(data, 0));/*получим байты начиная с нулевого МАС адрес*/
            result.setMacSrc(byteArrayToMac(data, 6));
            /*получение данных для Типа*/
            result.setType(byteArrayToType(data, datasetType));
            /*получение данных для APPID*/
            result.setAppID(byteArrayToAPPID(data, datasetAPPID));
            /*получение данных для svId*/
            result.setSvID(byteArrayToSVID(data, datasetSvID));
            /*получение данных для SmpCnt*/
            result.setSmpCount(byteArrayToSmpCnt(data, length - datasetSmpCnt));
            /*получение данных для confRef*/
            result.setConfRev(byteArrayToConfRef(data, length - datasetСonfRef));
            /*получение данных для SmpSynch*/
            result.setSmpSynch(byteArrayToSmpSynch(data, length - datasetSmpSynch));
            /*получение данных для фазы А*/
            result.getDataset().setInstIa(byteArrayToInt(data, length - datasetSizeForFaseA) /100.0 );
            result.getDataset().setqIa(byteArrayToQuality(data, length - datasetSizeForFaseA));
            result.getDataset().setInstUa(byteArrayToInt(data, length - (datasetSizeForFaseA-datasetForU)) /100.0 );
            result.getDataset().setqUa(byteArrayToQuality(data, length - (datasetSizeForFaseA-datasetForU)));
            /*получение данных для фазы B*/
            result.getDataset().setInstIb(byteArrayToInt(data, length - datasetSizeForFaseB) /100.0 );
            result.getDataset().setqIb(byteArrayToQuality(data, length - datasetSizeForFaseB));
            result.getDataset().setInstUb(byteArrayToInt(data, length - (datasetSizeForFaseB-datasetForU)) /100.0 );
            result.getDataset().setqUb(byteArrayToQuality(data, length - (datasetSizeForFaseB-datasetForU)));
            /*получение данных для фазы C*/
            result.getDataset().setInstIc(byteArrayToInt(data, length - datasetSizeForFaseC) /100.0 );
            result.getDataset().setqIc(byteArrayToQuality(data, length - datasetSizeForFaseC));
            result.getDataset().setInstUc(byteArrayToInt(data, length - (datasetSizeForFaseC-datasetForU)) /100.0 );
            result.getDataset().setqUc(byteArrayToQuality(data, length - (datasetSizeForFaseC-datasetForU)));
            /*получение данных для нейтрали*/
            result.getDataset().setInstIn(byteArrayToInt(data, length - datasetSizeForFaseNeutral) /100.0 );
            result.getDataset().setqIn(byteArrayToQuality(data, length - datasetSizeForFaseNeutral));
            result.getDataset().setInstUn(byteArrayToInt(data, length - (datasetSizeForFaseNeutral-datasetForU)) /100.0 );
            result.getDataset().setqUn(byteArrayToQuality(data, length - (datasetSizeForFaseNeutral-datasetForU)));

            //System.out.println((result.getDataset().getInstIa()));

            return Optional.of(result);
        }catch (Exception e){
            log.error(("Cannot parse sv packet"));
        }

        return Optional.empty(); // Означает что результата нема
    };
    public static String byteArrayToSVID(byte[] b, int offset){
        return  String.format("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
                b[offset],
                b[1+offset],
                b[2+offset],
                b[3+offset],
                b[4+offset],
                b[5+offset],
                b[6+offset],
                b[7+offset],
                b[8+offset],
                b[9+offset]
        );
    };



    public static  String byteArrayToMac(byte[] b, int offset){  //хоти получит МАС адрес из масиива byte
        return  String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                b[offset],
                b[1+offset],
                b[2+offset],
                b[3+offset],
                b[4+offset],
                b[5+offset]
                );
    };

    public  static  String byteArrayToType(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/
        return  String.format("0x%02x%02x",
                b[offset],
                b[1+offset]
        );
    }
    public  static  String byteArrayToAPPID(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/
        return  String.format("0x%02x%02x",
                b[offset],
                b[1+offset]
        );
    }
    public  static  int byteArrayToInt(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
        * символы у данного числа, в С++ этого не делают*/

        return b[offset+3] & 0xFF | (b[offset+2] & 0xFF) << 8 | (b[offset+1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }
    public  static  int byteArrayToConfRef(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/

        return b[offset+3] & 0xFF | (b[offset+2] & 0xFF) << 8 | (b[offset+1] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }

    public  static  int byteArrayToSmpCnt(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/

        return b[offset+1] & 0xFF | (b[offset] & 0xFF) << 8;
    }
    public  static  int byteArrayToSmpSynch(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/

        return b[offset] & 0xFF;
    }
    public  static  int byteArrayToQuality(byte[] b, int offset){
        /*производим битовые операции берем нулевой байт, и домножаем его на FF, чтобы отбросить
         * символы у данного числа, в С++ этого не делают*/

        return b[offset+7] & 0xFF | (b[offset+6] & 0xFF) << 8 | (b[offset+5] & 0xFF) << 16 | (b[offset+4] & 0xFF) << 24;
    }




}
