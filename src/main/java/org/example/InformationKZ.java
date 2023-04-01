package org.example;

import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Data
@Slf4j
public class InformationKZ {

    private double minCurrent;

    private double minVoltage;
    private double maxCurrent;

    private double maxVoltage;

    private String information;

    private double time;


    @Override
    public String toString() {
        System.out.println("_________________________________________________________________________________________________________");
         log.warn("Информация аварийного режима, действующие значения токов и напряжений: " +
                 "Минимальный ток КЗ = {} мА, " +
                 "Максимальный ток КЗ = {} мА, " +
                 "Минимальное напряжение КЗ = {} мВ," +
                 "Максимльное напряжение КЗ = {} мВ," +
                 "Тип короткого замыкания - {}," +
                 "длительность аварийного режима = {},", this.minCurrent, this.maxCurrent, this.minVoltage, this.maxVoltage, this.information, this.time);
        return "_________________________________________________________________________________________________________";
    }
}
