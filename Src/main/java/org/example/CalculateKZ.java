package org.example;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Objects;

public class CalculateKZ {
    //
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by FernFlower decompiler)
//
        private final double setting = 4500.0;


        private ArrayList arrayKZ = new ArrayList();
        private double maxValuefaseA = 0.0;
        private double voltageA = 0.0;
        private double maxValuefaseB = 0.0;
        private double voltageB = 0.0;
        private double maxValuefaseC = 0.0;
        private double voltageC = 0.0;
        private int number = 0;
        private double timeKZ = 0.0;
        private int typeKZ = 0;
        private InformationNormal informationNormal = new InformationNormal();
        private String info = "";
        private ArrayList<Double> currentKZ = new ArrayList();
        private ArrayList<Double> voltageKZ = new ArrayList();
        private ArrayList<Double> currentNormal = new ArrayList();
        private ArrayList<Double> voltageNormal = new ArrayList();
        private double time = 0.0;

        public CalculateKZ() {
        }

        public void findMaxValue(SVPacket packetNew) {
            this.time += 0.002;
            ++this.number;
            if (Math.abs(packetNew.getDataset().getInstIa() / Math.sqrt(2.0)) > this.maxValuefaseA) {
                this.maxValuefaseA = Math.abs(packetNew.getDataset().getInstIa() / Math.sqrt(2.0));
                this.voltageA = Math.abs(packetNew.getDataset().getInstUa() / Math.sqrt(2.0));
            }

            if (Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2.0)) > this.maxValuefaseB) {
                this.maxValuefaseB = Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2.0));
                this.voltageB = Math.abs(packetNew.getDataset().getInstUb() / Math.sqrt(2.0));
            }

            if (Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2.0)) > this.maxValuefaseC) {
                this.maxValuefaseC = Math.abs(packetNew.getDataset().getInstIc() / Math.sqrt(2.0));
                this.voltageC = Math.abs(packetNew.getDataset().getInstUc() / Math.sqrt(2.0));
            }

            if (this.number == 10) {
                this.findKZ(packetNew);
                this.maxValuefaseA = 0.0;
                this.maxValuefaseB = 0.0;
                this.maxValuefaseC = 0.0;
                this.voltageA = 0.0;
                this.voltageB = 0.0;
                this.voltageC = 0.0;
                this.number = 0;
            }

        }

        public void findKZ(SVPacket packetNew) {
            double var10000 = this.maxValuefaseA;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                this.currentKZ.add(this.maxValuefaseA);
                this.voltageKZ.add(this.voltageA);
            } else {
                this.currentNormal.add(this.maxValuefaseA);
                this.voltageNormal.add(this.voltageA);
            }

            var10000 = this.maxValuefaseB;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                this.currentKZ.add(this.maxValuefaseB);
                this.voltageKZ.add(this.voltageB);
            } else {
                this.currentNormal.add(this.maxValuefaseB);
                this.voltageNormal.add(this.voltageB);
            }

            var10000 = this.maxValuefaseC;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                this.currentKZ.add(this.maxValuefaseC);
                this.voltageKZ.add(this.voltageC);
            } else {
                this.currentNormal.add(this.maxValuefaseC);
                this.voltageNormal.add(this.voltageC);
            }

            Collections.sort(this.currentNormal);
            Collections.sort(this.voltageNormal);
            this.informationNormal.setMinCurrent((Double)this.currentNormal.get(0));
            this.informationNormal.setMaxCurrent((Double)this.currentNormal.get(this.currentNormal.size() - 1));
            this.informationNormal.setMinVoltage((Double)this.voltageNormal.get(0));
            this.informationNormal.setMaxVoltage((Double)this.voltageNormal.get(this.voltageNormal.size() - 1));
            var10000 = this.maxValuefaseA;
            Objects.requireNonNull(this);
            if (var10000 <= 4500.0) {
                var10000 = this.maxValuefaseB;
                Objects.requireNonNull(this);
                if (var10000 <= 4500.0) {
                    var10000 = this.maxValuefaseC;
                    Objects.requireNonNull(this);
                    if (var10000 <= 4500.0) {
                        if (this.timeKZ != 0.0) {
                            InformationKZ informationKZ = new InformationKZ();
                            informationKZ.setInformation(this.info);
                            informationKZ.setTime(this.timeKZ);
                            Collections.sort(this.currentKZ);
                            Collections.sort(this.voltageKZ);
                            informationKZ.setMinCurrent((Double)this.currentKZ.get(0));
                            informationKZ.setMaxCurrent((Double)this.currentKZ.get(this.currentKZ.size() - 1));
                            informationKZ.setMinVoltage((Double)this.voltageKZ.get(0));
                            informationKZ.setMaxVoltage((Double)this.voltageKZ.get(this.currentKZ.size() - 1));
                            this.arrayKZ.add(informationKZ);
                        }

                        this.timeKZ = 0.0;
                        return;
                    }
                }
            }

            int quantity = 0;
            this.timeKZ += 0.01;
            var10000 = this.maxValuefaseA;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                ++quantity;
            }

            var10000 = this.maxValuefaseB;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                ++quantity;
            }

            var10000 = this.maxValuefaseC;
            Objects.requireNonNull(this);
            if (var10000 > 4500.0) {
                ++quantity;
            }

            if (this.typeKZ == 0) {
                if (quantity == 3) {
                    this.info = "Трехфазное короткое замыкание";
                    this.typeKZ = 3;
                } else if (quantity == 2) {
                    this.info = "Двухфазное короткое замыкание";
                    this.typeKZ = 2;
                } else {
                    this.info = "Однофазное короткое замыкание";
                    this.typeKZ = 1;
                }
            } else if (quantity != this.typeKZ) {
                InformationKZ informationKZ = new InformationKZ();
                informationKZ.setInformation(this.info);
                informationKZ.setTime(this.timeKZ);
                Collections.sort(this.currentKZ);
                Collections.sort(this.voltageKZ);
                informationKZ.setMinCurrent((Double)this.currentKZ.get(0));
                informationKZ.setMaxCurrent((Double)this.currentKZ.get(this.currentKZ.size() - 1));
                informationKZ.setMinVoltage((Double)this.voltageKZ.get(0));
                informationKZ.setMaxVoltage((Double)this.voltageKZ.get(this.currentKZ.size() - 1));
                this.arrayKZ.add(informationKZ);
                if (quantity == 3) {
                    this.info = "Трехфазное короткое замыкание";
                    this.typeKZ = 3;
                } else if (quantity == 2) {
                    this.info = "Двухфазное короткое замыкание";
                    this.typeKZ = 2;
                } else {
                    this.info = "Однофазное короткое замыкание";
                    this.typeKZ = 1;
                }

                this.timeKZ = 0.0;
            }

        }

        public double getSetting() {
            Objects.requireNonNull(this);
            return 4500.0;
        }

        public ArrayList getArrayKZ() {
            return this.arrayKZ;
        }

        public double getMaxValuefaseA() {
            return this.maxValuefaseA;
        }

        public double getVoltageA() {
            return this.voltageA;
        }

        public double getMaxValuefaseB() {
            return this.maxValuefaseB;
        }

        public double getVoltageB() {
            return this.voltageB;
        }

        public double getMaxValuefaseC() {
            return this.maxValuefaseC;
        }

        public double getVoltageC() {
            return this.voltageC;
        }

        public int getNumber() {
            return this.number;
        }

        public double getTimeKZ() {
            return this.timeKZ;
        }

        public int getTypeKZ() {
            return this.typeKZ;
        }

        public InformationNormal getInformationNormal() {
            return this.informationNormal;
        }

        public String getInfo() {
            return this.info;
        }

        public ArrayList<Double> getCurrentKZ() {
            return this.currentKZ;
        }

        public ArrayList<Double> getVoltageKZ() {
            return this.voltageKZ;
        }

        public ArrayList<Double> getCurrentNormal() {
            return this.currentNormal;
        }

        public ArrayList<Double> getVoltageNormal() {
            return this.voltageNormal;
        }

        public double getTime() {
            return this.time;
        }
    }


