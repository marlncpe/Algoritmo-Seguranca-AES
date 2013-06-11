<?php
	set_time_limit(10);

	class Seguranca {

		private $sbox;	// Rijndael S-box
		private $rsbox;	// Rijndael Inverted S-box
		private $rcon;	// Rijndael Rcon

		public function Seguranca(){
			$this->sbox =  array(0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
								, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
								, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
								, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
								, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
								, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
								, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
								, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
								, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
								, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
								, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
								, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
								, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
								, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
								, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
								, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
			);
		}

		public function gerarChave() {
			$chaveStr = dechex(rand(0, 15)) . dechex(rand(16, 255)) . uniqid() . dechex(rand(0, 15)) . dechex(rand(16, 255)) . uniqid();

			$key = array();
			for($i = 0; $i < strlen($chaveStr); $i += 2) {
				$key[] = hexdec($chaveStr{$i} . $chaveStr{$i + 1});
			}

			return $key;
		}

		public function cifrar($valor, $key) {
			$cifrado = $this->converteStringParaMatriz($valor);
			
			foreach ($cifrado as $k => $matriz) {
				//$cifrado[$k] = $this->byteSub($matriz);
				$cifrado[$k] = $this->byteSub($matriz);
				$cifrado[$k] = $this->shiftRow($cifrado[$k]);
				$cifrado[$k] = $this->mixColumns($cifrado[$k]);
				$cifrado[$k] = $this->AddRoundKey($cifrado[$k], $key);
			}

			// ...
			return $this->converteMatrizParaString($cifrado);
		}

		public function decifrar($valor, $key) {
			$decifrado = $this->converteStringParaMatriz($valor);
			
			foreach ($decifrado as $k => $matriz) {
				//$decifrado[$k] = $this->unbyteSub($matriz);
				$cifrado[$k] = $this->AddRoundKey($matriz, $key);
				$decifrado[$k] = $this->unmixColumns($cifrado[$k]);
				$decifrado[$k] = $this->unshiftRow($decifrado[$k]);
				$decifrado[$k] = $this->unbyteSub($decifrado[$k]);
			}
			// ...
			return $this->converteMatrizParaString($decifrado);
		}

		private function getTamanhoKey() {
			return count($this->key); // 16 bytes
		}

		private function converteStringParaMatriz($valor) {
			$matrizes = array();

			if(!is_array($valor)) {
				for($i = 0; $i < strlen($valor); $i += 16){
					
					$dif = strlen($valor) - $i;
					if($dif < 16){
						for($j = $dif; $j < 16; $j++){
							$valor .= "\0";
						}
					}

					$matrizTemp = array(
						  array(ord($valor{$i}), ord($valor{$i+1}), ord($valor{$i+2}), ord($valor{$i+3}))
						, array(ord($valor{$i+4}), ord($valor{$i+5}), ord($valor{$i+6}), ord($valor{$i+7}))
						, array(ord($valor{$i+8}), ord($valor{$i+9}), ord($valor{$i+10}), ord($valor{$i+11}))
						, array(ord($valor{$i+12}), ord($valor{$i+13}), ord($valor{$i+14}), ord($valor{$i+15}))
					);

					$matrizes[] = $matrizTemp;
				}
			}

			return $matrizes;
		}

		private function converteMatrizParaString($matrizes) {
			$str = "";

			foreach ($matrizes as $k => $matriz) {
				$str .= chr($matriz[0][0]) . chr($matriz[0][1]) . chr($matriz[0][2]) . chr($matriz[0][3])
					.	chr($matriz[1][0]) . chr($matriz[1][1]) . chr($matriz[1][2]) . chr($matriz[1][3])
					.	chr($matriz[2][0]) . chr($matriz[2][1]) . chr($matriz[2][2]) . chr($matriz[2][3])
					.	chr($matriz[3][0]) . chr($matriz[3][1]) . chr($matriz[3][2]) . chr($matriz[3][3]);
			}

			return $str;
		}

		// Metodos privates | etapas da cifragem/decifragem
		private function byteSub($matriz) {
			for($i = 0; $i < 4; $i++){
				$matriz[$i][0] = $this->sbox[$matriz[$i][0]];
				$matriz[$i][1] = $this->sbox[$matriz[$i][1]];
				$matriz[$i][2] = $this->sbox[$matriz[$i][2]];
				$matriz[$i][3] = $this->sbox[$matriz[$i][3]];
			}

			return $matriz;
		}

		private function shiftRow($matriz) {
			foreach($matriz as $i => $linha){
				if($i > 0){
					foreach($linha as $j => $char){
						$pos = $j - $i;
						if($pos < 0) {
							$pos += 4;
						}

						$matriz[$i][$pos] = $linha[$j];
					}
				}
			}

			return $matriz;
		}

		private function mixColumns($matriz) {
			foreach($matriz as $i => $linha) {
				$matriz[$i] = $this->mixColumn($linha);
			}

			return $matriz;
		}

		private function mixColumn($linha) {
			$linhaClone = $linha;
			$mult = array(14, 9, 13, 11);

			$linha[0] = ($this->galoisMultiplication($linhaClone[0], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[3]));
			$linha[1] = ($this->galoisMultiplication($linhaClone[1], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[3]));
			$linha[2] = ($this->galoisMultiplication($linhaClone[2], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[3]));
			$linha[3] = ($this->galoisMultiplication($linhaClone[3], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[3]));

			return $linha;
		}

		private function galoisMultiplication($a, $b) {
			$p = 0;

			for($i = 0; $i < 8; $i++) {
				if(($b & 1) == 1 ){
					$p ^= $a;
				}

				if($p > 0x100) {
					$a ^= 0x100;
				}

				$hiBitSet = $a & 0x80;
				$a <<= 1;

				if($a > 0x100) {
					$a ^= 0x100;
				}

				if($hiBitSet == 0x80) {
					$a ^= 0x1b;
				}

				if($a > 0x100) {
					$a ^= 0x100;
				}

				$b >>= 1;

				if($b > 0x100) {
					$b ^= 0x100;
				}
			}

			return $p;
		}

		private function AddRoundKey($matriz, $key) {
			foreach($matriz as $i => $linha) {
				foreach($linha as $j => $byte) {
					$matriz[$i][$j] ^= $key[$i + $j];
				}
			}

			return $matriz;
		}

		private function unshiftRow($matriz) {
			foreach($matriz as $i => $linha){
				if($i > 0){
					foreach($linha as $j => $char){
						$pos = $j + $i;
						if($pos > 3) {
							$pos -= 4;
						}

						$matriz[$i][$pos] = $linha[$j];
					}
				}
			}

			return $matriz;
		}

		private function unbyteSub($matriz) {
			for($i = 0; $i < 4; $i++) {
				$matriz[$i][0] = array_search($matriz[$i][0], $this->sbox);
				$matriz[$i][1] = array_search($matriz[$i][1], $this->sbox);
				$matriz[$i][2] = array_search($matriz[$i][2], $this->sbox);
				$matriz[$i][3] = array_search($matriz[$i][3], $this->sbox);
			}

			return $matriz;
		}

		private function unmixColumns($matriz) {
			foreach($matriz as $i => $linha) {
				$matriz[$i] = $this->unmixColumn($linha);
			}

			return $matriz;
		}

		private function unmixColumn($linha) {
			$linhaClone = $linha;
			$mult = array(2, 1, 1, 3);

			$linha[0] = ($this->galoisMultiplication($linhaClone[0], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[3]));
			$linha[1] = ($this->galoisMultiplication($linhaClone[1], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[3]));
			$linha[2] = ($this->galoisMultiplication($linhaClone[2], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[3], $mult[3]));
			$linha[3] = ($this->galoisMultiplication($linhaClone[3], $mult[0])) ^ ($this->galoisMultiplication($linhaClone[2], $mult[1])) ^ ($this->galoisMultiplication($linhaClone[1], $mult[2])) ^ ($this->galoisMultiplication($linhaClone[0], $mult[3]));

			return $linha;
		}
	}
	/* FIM CLASSE SEGURANCA */


	$seguranca = new Seguranca();

	$key = $seguranca->gerarChave();
	var_dump($key);
	print "<br /><br />";

	$str = "teste de criptografia AES - 123";
	$cifrado = $seguranca->cifrar($str, $key);
	//$key[0] = 255;
	$decifrado = $seguranca->decifrar($cifrado, $key);

	print "<pre>";
	
	print("Original:  ");
	var_dump($str);
	
	print "<hr />";
	
	print("Cifrado:   ");
	var_dump($cifrado);
	
	print "<hr />";
	
	print("Decifrado: ");
	var_dump($decifrado);

	print "</pre>";
?>
