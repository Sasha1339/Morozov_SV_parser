package org.example;


import lombok.Data;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Data
public class InformationNormal {
    private double minCurrent;

    private double minVoltage;
    private double maxCurrent;

    private double maxVoltage;

    @Override
    public String toString() {
        System.out.println("_________________________________________________________________________________________________________");
        log.info("Информация нормального режима, действующие значения токов и напряжений: " +
                "Минимальный ток = {} мА, " +
                "Максимальный ток = {} мА, " +
                "Минимальное напряжение= {} мВ," +
                "Максимльное напряжение" +
                "= {} мВ,", this.minCurrent, this.maxCurrent, this.minVoltage, this.maxVoltage);
        return "_________________________________________________________________________________________________________";
    }
}
