# SPRING PLUS

## Level 3 Q12. AWS 활용

### 12-1. EC2
health check API : 
http://3.38.102.49:8080/actuator/health

![img_10.png](images/img_10.png)

### 12-2. RDS
![img_11.png](images/img_11.png)
![img_13.png](images/img_13.png)
![img_14.png](images/img_14.png)

### 12-3. S3
Presigned URL - 유효기간 7일
https://spring-plus-bucket-hanbi.s3.ap-northeast-2.amazonaws.com/uploads/35fa9c34-d428-4096-868c-bae4f498a8a9_aws_logo.png?X-Amz-Security-Token=IQoJb3JpZ2luX2VjEN3%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDmFwLW5vcnRoZWFzdC0yIkcwRQIgaZ5IynSWifHXSQqn4cNbNJ0%2BXVL8eUDaJNbT0DLoHtsCIQCBTUyNFJ78dIO2eVkW%2F3ZG6n2Mw3njj4jdKaeovvJjfSrSBQim%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F8BEAAaDDE3MDYzODE5OTcxNiIMHK%2Fd354sYWV46PNQKqYF9tlZaZWCCZaesu%2Fljb0Qr6rHPaapsEW0ZeE%2FeOE0DpKZXVgPORgET7gJINhdCYYtEXTfD9FSKse%2BP0h2KMcxqtbxUpbq4QIbnenoM2%2B%2BCPLWEY7HWE2RJaF8p80T8YFwCwJ2IQLMJ2YXAKZYzvCAKqWlONdPXXIZlYoiYK%2Bg2ZM79PnIRs2IXNUE%2BxWEVmfrE7aKy5eust2rEhUYZ94ZYI1GUrhRaeIz4XcWRGHxsTuF5UktTAnI%2Blg3tYjuVsb%2FXRNFtzEoE31N3u%2BfkS8XezWrcKs3Fk4N40xHEitxG%2FKs8oVxDkPeG%2FRKhvJdv6FNOydI%2BkQ9m4whumFmP8yak%2FpnUZavKqSht7QnnA9It0pJXU9o8YnY4YKba9j0ywYjNyW36azgJNdsQZ2w0Xmn7GNxoL4E4iAjzoJXGEA0HV5Chjji%2BMcXz4WWo%2F%2FmTwQjn%2BCbX%2FNWcDWy0lX5OS4cA302naajaIwSHs6uMNkBVhJU4e%2FNuznBo9pT%2Fg0aXESnI3t7pXQGY7RRVBaC0kHjp2COr%2BoTxlMzWEVRR0s0Yd0JXHImpVOtAUeBuxIU3AWn10djRB6eJ1WDoq%2Bbkcf9yIjdaal%2BhhDErgeYLlvPr77%2FFgypwXxU4t%2B0Brw5cnPVr1W1sLFWucCvDA%2Fy%2Bg%2BnlCE%2FH0G5IyoYcJpOmerNVI59t3MvwIekq2L7bjXu25Y7QwhiEuj9oOjJlanb%2FMFJOS5uCNqd2YZ3SMmbQ6pJ7%2F0SgVZtUhQxEi1VBpZmdeOoJkaXMvTAXfRsyhPV1GKCEsLTOtLb7at2vUOqnzhAZTA26bYINqAeRTogFm3C23ZQUJvYoz9E9nB8hqf4774udHo7JMpB%2F3XHgotTwmMFaLmjczevixU6ljFn5cQElNcCKKcFLvTRMNaVnc0GOrEBF6L6e7wIgUjdqMGbDQXjHI2UnCLekn0Qw0EIIHGBUOwUXSD%2BGsSwslDQEOpJbY%2BTKBaymNza41%2FlfmCBXA%2BGmvcRKHDMPix4LK0UgZS%2BdVuG4P5%2FfrXjw%2FlkSgEDKXUTXAfq51V86Bl519bimACGFXK2bMOUCjX2dr9AXcw69YhuGPjKY3NJ4Am7i7S3qjgPSPFKBPpEDx0Ap4EXmse21UaSa2MfpcOsT9P7Af%2BkiEIZ&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=20260303T213910Z&X-Amz-SignedHeaders=host&X-Amz-Credential=ASIASPOWUJOSIOPMINDE%2F20260303%2Fap-northeast-2%2Fs3%2Faws4_request&X-Amz-Expires=604800&X-Amz-Signature=f0822c703d1c72d1642bb2028a4f3b6fcb9163799a5bf2938afde89068652dcb


---
## Level 3 Q13. 대용량 데이터 처리

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



