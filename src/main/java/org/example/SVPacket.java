package org.example;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;

@Setter @Getter
public class SVPacket {
    /*этот класс занимается хранением данных, которые будут парсится из пойманого запроса в
    * SVDecoder*/

    /*В этом классе нужно создать МАС адреса источника и назначения*/
    private String macDst;
    private String macSrc;


    private  String type;
    /*далее АРРID*/
    private String appID;
    private String svID;
    private int smpCount;
    private int confRev;
    private int smpSynch;
    private Dataset dataset = new Dataset();

    public void setDataset(Dataset dataset) {
        this.dataset = dataset;
    }


    public Dataset getDataset() {
        return dataset;
    }

    class Dataset{
        private double instIa; //мгновенная величина ток
        private int qIa; //качество тока
        private double instIb;
        private int qIb;
        private double instIc;
        private int qIc;
        private double instIn;
        private int qIn;

        private double instUa; //мгновенная величина напряжения
        private int qUa; //качество напряжения
        private double instUb;
        private int qUb;
        private double instUc;
        private int qUc;
        private double instUn;
        private int qUn;

        public double getInstIa() {
            return instIa;
        }

        public int getqIa() {
            return qIa;
        }

        public double getInstIb() {
            return instIb;
        }

        public int getqIb() {
            return qIb;
        }

        public double getInstIc() {
            return instIc;
        }

        public int getqIc() {
            return qIc;
        }

        public double getInstIn() {
            return instIn;
        }

        public int getqIn() {
            return qIn;
        }

        public double getInstUa() {
            return instUa;
        }

        public int getqUa() {
            return qUa;
        }

        public double getInstUb() {
            return instUb;
        }

        public int getqUb() {
            return qUb;
        }

        public double getInstUc() {
            return instUc;
        }

        public int getqUc() {
            return qUc;
        }

        public double getInstUn() {
            return instUn;
        }

        public int getqUn() {
            return qUn;
        }

        public void setInstIa(double instIa) {
            this.instIa = instIa;
        }

        public void setqIa(int qIa) {
            this.qIa = qIa;
        }

        public void setInstIb(double instIb) {
            this.instIb = instIb;
        }

        public void setqIb(int qIb) {
            this.qIb = qIb;
        }

        public void setInstIc(double instIc) {
            this.instIc = instIc;
        }

        public void setqIc(int qIc) {
            this.qIc = qIc;
        }

        public void setInstIn(double instIn) {
            this.instIn = instIn;
        }

        public void setqIn(int qIn) {
            this.qIn = qIn;
        }

        public void setInstUa(double instUa) {
            this.instUa = instUa;
        }

        public void setqUa(int qUa) {
            this.qUa = qUa;
        }

        public void setInstUb(double instUb) {
            this.instUb = instUb;
        }

        public void setqUb(int qUb) {
            this.qUb = qUb;
        }

        public void setInstUc(double instUc) {
            this.instUc = instUc;
        }

        public void setqUc(int qUc) {
            this.qUc = qUc;
        }

        public void setInstUn(double instUn) {
            this.instUn = instUn;
        }

        public void setqUn(int qUn) {
            this.qUn = qUn;
        }
    }


}
