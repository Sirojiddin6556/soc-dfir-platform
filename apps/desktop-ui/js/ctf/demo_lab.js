/**
 * Seeds a default realistic CTF competition with 5 rich challenges
 * across crypto, reverse, forensics, web, and stego.
 */
export async function seedDemoLab(workspaceStore) {
  try {
    let comp = await workspaceStore.createCompetition({
      name: 'SOC/DFIR Cyber Challenge 2026',
      description: 'Тренировочный полигон для отработки навыков расследования, криптографии и реверс-инжиниринга'
    });
    const compId = comp?.id || comp?.competition_id || workspaceStore.getState().activeCompetitionId;
    if (!compId) return;

    const challengesData = [
      {
        name: 'XOR Obfuscated Beacon',
        category: 'crypto',
        points: 100,
        description: 'Перехвачен бинарный маяк C2. Известно, что полезная нагрузка замаскирована однобайтным XOR ключом 0x5A. Декодируйте артефакт в Recipe Studio и найдите флаг.',
        expected_flag: 'flag{x0r_c2_b34c0n_d3c0d3d_2026}'
      },
      {
        name: 'Crackme ELF Header & String Hunt',
        category: 'reverse',
        points: 150,
        description: 'Найден скомпилированный бинарный модуль. Исследуйте заголовки и строковые литералы в Hex Viewer / Terminal Strings, чтобы обнаружить мастер-пароль.',
        expected_flag: 'flag{h3x_v13w3r_str1ngs_m4st3r}'
      },
      {
        name: 'Memory Dump Infiltration',
        category: 'forensics',
        points: 200,
        description: 'Дамп сегмента памяти процесса powershell.exe содержит подозрительный закодированный фрагмент команды. Расшифруйте Base64 цепочку.',
        expected_flag: 'flag{m3m0ry_f0r3ns1cs_p0w3rsh3ll}'
      },
      {
        name: 'Malicious JWT Token & Forgery',
        category: 'web',
        points: 100,
        description: 'Токен авторизации перехвачен в сессии аналитика. Исследуйте алгоритм "none" и payload в Recipe Studio.',
        expected_flag: 'flag{jwt_alg_n0n3_vuln3r4bl3}'
      },
      {
        name: 'High-Entropy Stego Carrier',
        category: 'stego',
        points: 150,
        description: 'Файл содержит аномальный всплеск энтропии в хвостовом сегменте. Исследуйте его через Entropy Minimap и извлеките скрытые данные.',
        expected_flag: 'flag{3ntr0py_m1n1m4p_st3g0_f0und}'
      }
    ];

    for (const ch of challengesData) {
      try {
        await workspaceStore.createChallenge({
          name: ch.name,
          category: ch.category,
          points: ch.points,
          expected_flag: ch.expected_flag
        });
      } catch (_) {}
    }

    await workspaceStore.loadCompetition(compId);
  } catch (e) {
    console.warn('[CtfApp] Seed demo failed:', e);
  }
}
