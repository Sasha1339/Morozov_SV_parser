package org.example;

import lombok.Data;
import lombok.Getter;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Getter
public class CalculateKZ {


    private final double setting = 4500.0;
    private ArrayList arrayKZ = new ArrayList<InformationKZ>();

    private double maxValuefaseA = 0.0;
    private double voltageA = 0.0;
    private double maxValuefaseB = 0.0;
    private double voltageB = 0.0;
    private double maxValuefaseC = 0.0;
    private double voltageC = 0.0;
    private int number = 0;
    private double timeKZ = 0.000;
    private int  typeKZ = 0;

    private InformationNormal informationNormal = new InformationNormal();
    private String info = "";
    private ArrayList<Double> currentKZ = new ArrayList<Double>();
    private ArrayList<Double> voltageKZ = new ArrayList<Double>();
    private ArrayList<Double> currentNormal = new ArrayList<Double>();
    private ArrayList<Double> voltageNormal = new ArrayList<Double>();
    private double time = 0.0;



    public void findMaxValue(SVPacket packetNew) {
            this.time += 0.002;
            number += 1;
            if (Math.abs(packetNew.getDataset().getInstIa() / Math.sqrt(2)) > this.maxValuefaseA) {
                this.maxValuefaseA = Math.abs(packetNew.getDataset().getInstIa() / Math.sqrt(2));
                this.voltageA = Math.abs(packetNew.getDataset().getInstUa() / Math.sqrt(2));
            }
            if (Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2)) > this.maxValuefaseB) {
                this.maxValuefaseB = Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2));
                this.voltageB = Math.abs(packetNew.getDataset().getInstUb() / Math.sqrt(2));
            }
            if (Math.abs(packetNew.getDataset().getInstIb() / Math.sqrt(2)) > this.maxValuefaseC) {
                this.maxValuefaseC = Math.abs(packetNew.getDataset().getInstIc() / Math.sqrt(2));
                this.voltageC = Math.abs(packetNew.getDataset().getInstUc() / Math.sqrt(2));
            }

<<<<<<< HEAD:Src/Главная/java/org/пример/CalculateKZ.java
            if (number == 5){
=======
            if (number == 10){
>>>>>>> a87da6d (Second Commit):src/main/java/org/example/CalculateKZ.java
                findKZ(packetNew);
                this.maxValuefaseA = 0.0;
                this.maxValuefaseB = 0.0;
                this.maxValuefaseC = 0.0;
                this.voltageA = 0.0;
                this.voltageB = 0.0;
                this.voltageC = 0.0;
                number = 0;
            }

    }

    public void findKZ(SVPacket packetNew){
        if (this.maxValuefaseA > this.setting){
            currentKZ.add(this.maxValuefaseA);
            voltageKZ.add(this.voltageA);
        }else{
            currentNormal.add(this.maxValuefaseA);
            voltageNormal.add(this.voltageA);
        }
        if (this.maxValuefaseB > this.setting){
            currentKZ.add(this.maxValuefaseB);
            voltageKZ.add(this.voltageB);
        }else{
            currentNormal.add(this.maxValuefaseB);
            voltageNormal.add(this.voltageB);
        }
        if (this.maxValuefaseC > this.setting){
            currentKZ.add(this.maxValuefaseC);
            voltageKZ.add(this.voltageC);
        }else{
            currentNormal.add(this.maxValuefaseC);
            voltageNormal.add(this.voltageC);
        }
        Collections.sort(currentNormal);
        Collections.sort(voltageNormal);
        informationNormal.setMinCurrent(currentNormal.get(0));
        informationNormal.setMaxCurrent(currentNormal.get(currentNormal.size()-1));
        informationNormal.setMinVoltage(voltageNormal.get(0));
        informationNormal.setMaxVoltage(voltageNormal.get(voltageNormal.size()-1));
        if (this.maxValuefaseA <= this.setting && this.maxValuefaseB <= this.setting && this.maxValuefaseC <= this.setting){
            if (timeKZ != 0.0){
                InformationKZ informationKZ = new InformationKZ();
                informationKZ.setInformation(this.info);
                informationKZ.setTime(this.timeKZ);
                Collections.sort(currentKZ);
                Collections.sort(voltageKZ);
                informationKZ.setMinCurrent(currentKZ.get(0));
                informationKZ.setMaxCurrent(currentKZ.get(currentKZ.size()-1));
                informationKZ.setMinVoltage(voltageKZ.get(0));
                informationKZ.setMaxVoltage(voltageKZ.get(currentKZ.size()-1));
                this.arrayKZ.add(informationKZ);

            }
            timeKZ = 0.0;

        } else {

            int quantity = 0;
            timeKZ += 0.01;
            if (this.maxValuefaseA > this.setting) {
                quantity += 1;
            }
            if (this.maxValuefaseB > this.setting) {
                quantity += 1;
            }
            if (this.maxValuefaseC > this.setting) {
                quantity += 1;
            }
            if (typeKZ == 0){
                if (quantity == 3) {
                    this.info = "Трехфазное короткое замыкание";
                    typeKZ = 3;
                } else if (quantity == 2) {
                    this.info = "Двухфазное короткое замыкание";
                    typeKZ = 2;
                } else {
                    this.info = "Однофазное короткое замыкание";
                    typeKZ = 1;
                }
            }else{
                if (quantity != typeKZ){

                    InformationKZ informationKZ = new InformationKZ();
                    informationKZ.setInformation(this.info);
                    informationKZ.setTime(this.timeKZ);
                    Collections.sort(currentKZ);
                    Collections.sort(voltageKZ);
                    informationKZ.setMinCurrent(currentKZ.get(0));
                    informationKZ.setMaxCurrent(currentKZ.get(currentKZ.size()-1));
                    informationKZ.setMinVoltage(voltageKZ.get(0));
                    informationKZ.setMaxVoltage(voltageKZ.get(currentKZ.size()-1));
                    this.arrayKZ.add(informationKZ);


                        if (quantity == 3) {
                            this.info = "Трехфазное короткое замыкание";
                            typeKZ = 3;
                        } else if (quantity == 2) {
                            this.info = "Двухфазное короткое замыкание";
                            typeKZ = 2;
                        } else {
                            this.info = "Однофазное короткое замыкание";
                            typeKZ = 1;
                        }
                    timeKZ = 0.0;
                }
            }
        }
    }




}
