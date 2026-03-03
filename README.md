# SPRING PLUS


---
## Level 3 Q11. 대용량 데이터 처리

#### 유저 검색 속도를 감소시킬 수 있는 여러 방법 탐색

<details>
<summary>1. 기본 - 6.13s</summary>
<div markdown="1">

![Q11_basicSearch.png](images/Q11_basicSearch.png)

</div>
</details>

<details>
<summary>2. QueryDsl로 필요한 컬럼만 조회(인덱스 X) - 4.33s</summary>
<div markdown="1">

![img_5.png](images/img_5.png)

</div>
</details>

<details>
<summary>3. 인덱스 추가 - 690ms</summary>
<div markdown="1">

![Q11_index.png](images/Q11_index.png)

</div>
</details>

<details>
<summary>4. 인덱스 추가 + 필요한 컬럼만 조회 - 20ms</summary>
<div markdown="1">

![img_6.png](images/img_6.png)

</div>
</details>

<details>
<summary>5. 캐싱 적용 - 9ms</summary>
<div markdown="1">

5-1. 첫번째 호출(DB 접근 후 반환) - 29ms
![img_9.png](images/img_9.png)

5-2. 두번째 호출(메모리에서 반환) - 9ms
![img_8.png](images/img_8.png)

</div>
</details>
<br/>

### 조회 속도 비교
|   | 방법                  | 조회 속도 | 설명                |
|---|---------------------|-------|-------------------|
| 1 | 인덱스 없음 (최초)         | 6.13s | Full Table Scan으로 500만 건 전체 탐색   |
| 2 | 필요한 컬럼만 조회(인덱스 X)   | 4.33s | 데이터 전송량 감소, 인덱스 대비 소폭 개선      |
| 3 | 인덱스 추가              | 690ms | B-Tree 인덱스로 빠른 탐색         |
| 4 | 인덱스 추가 + 필요한 컬럼만 조회 | 20ms  | B-Tree 탐색 + 데이터 전송량 감소로 추가 개선 |
| 5 | 캐싱 적용               | 9ms   | DB 접근 없이 메모리에서 반환 |



