package com.example.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.Date;

@Entity
@Table(name = "update_history")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UpdateHistory {
    @Id
    @Column(name = "update_history_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;
    @Column(name = "asset_id")
    private Long assetId;
    @Column(name = "value")
    private Double value;
    @Column(name = "value_prev")
    private Double valuePrev;
    @Column(name = "value_present")
    private Double valuePresent;
    @Column(name = "amount_month_prev")
    private Long amountMonthPrev;
    @Column(name = "amount_month_present")
    private Long amountMonthPresent;
    @Column(name = "note")
    private String note;
    @Column(name = "status")
    private String status;
    @Column(name = "user_update_id")
    private Long userUpdateId;
    @Column(name = "user_used_id")
    private Long userUsedId;
    @Column(name="date_update")
    private Date dateUpdate;
    @Column(name="create_at")
    private Date createAt;
}
