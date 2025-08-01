-- TABLES: lineitem,customer,nation,orders,part,partsupp,region,supplier

insert into customer select * from customer;
insert into lineitem select * from lineitem;
insert into nation select * from nation;
insert into orders select * from orders;
insert into part select * from part;
insert into partsupp select * from partsupp;
insert into region select * from region;
insert into supplier select * from supplier;
SELECT  /*+SET_VAR(enable_fallback_to_original_planner=false) */
  CAST(var["L_RETURNFLAG"] AS TEXT),
  CAST(var["L_LINESTATUS"] AS TEXT),
  SUM(CAST(var["L_QUANTITY"] AS DOUBLE))                                       AS SUM_QTY,
  SUM(CAST(var["L_EXTENDEDPRICE"] AS DOUBLE))                                  AS SUM_BASE_PRICE,
  SUM(CAST(var["L_EXTENDEDPRICE"] AS DOUBLE) * (1 - CAST(var["L_DISCOUNT"] AS DOUBLE)))               AS SUM_DISC_PRICE,
  SUM(CAST(var["L_EXTENDEDPRICE"] AS DOUBLE) * (1 - CAST(var["L_DISCOUNT"] AS DOUBLE)) * (1 + CAST(var["L_TAX"] AS DOUBLE))) AS SUM_CHARGE,
  AVG(CAST(var["L_QUANTITY"] AS DOUBLE))                                       AS AVG_QTY,
  AVG(CAST(var["L_EXTENDEDPRICE"] AS DOUBLE))                                  AS AVG_PRICE,
  AVG(CAST(var["L_DISCOUNT"] AS DOUBLE))                                       AS AVG_DISC,
  COUNT(*)                                              AS COUNT_ORDER
FROM
  lineitem
WHERE
  CAST(var["L_SHIPDATE"] AS DATE) <= DATE '1998-12-01' - INTERVAL '90' DAY
GROUP BY
CAST(var["L_RETURNFLAG"] AS TEXT),
CAST(var["L_LINESTATUS"] AS TEXT)
ORDER BY
CAST(var["L_RETURNFLAG"] AS TEXT),
CAST(var["L_LINESTATUS"] AS TEXT)
;
