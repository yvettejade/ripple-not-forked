#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Buffer.h>
#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/base_uint.h>
#include <xrpl/basics/contract.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/Bulletproof.h>
#include <xrpl/protocol/ConfidentialCrypto.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace xrpl::confidential {

class Bulletproof_test : public beast::unit_test::Suite
{
    // Proofs from an independent Python implementation of the paper's
    // prover with the same transcript and serialization, using
    // deterministic randomness.
    static constexpr char const* kSingle =
        "02E73ED8335E920478B44D72A213F4126A02381C70C1846A319F766EB2FAB740"
        "3C023D57AB000F1D00109BA5D94D79EB26214BBF65083C9BE92B7D30B5502F0A"
        "E38D0273E99E06A68F10C86BD21D7F426EE92DE64239A657DC211123C839807B"
        "46F79303BDE8C1F9C4DD55846CF2E647A879089C82E1BB7CF65A6B45A72E4B5F"
        "382AAF49BD3BDFEDD885FDA519DC51C0E9D2529D1AB390D0DFDF5A5B86525634"
        "3E08EFCF831B0A55C7BBCAC3308EE93F3009F15ED87BB147C0F118ADEF2281DA"
        "7623479B632CBA96D4A42E9D8EBEF6EF407C1FC6CE70FCF27DDEC96093D9E748"
        "D5477D470269FEBB2468B59AF8AB22AEBB0D205FE98086D6EA849C9743D7D66B"
        "EE124D3F43020D4D83BEE6AC27D4BB03B013FEFEA0513B25842252AC3E8CD377"
        "5F2F41F3B3CF02B62B3A8BAE5F8A28996048DFC86AD01274A69FE8D73678747B"
        "44225CE484999202A58B41F1AF9C853D342D3E7AAACEC71B284ECEDF968CFE18"
        "9610E0BBF076BFA90277CA35E5FAB125F2B7F7C25B486E0D3AE2A9737063DEBD"
        "F1F8CED7606F5E18DE028DBE137EA5435C8E2629A47DB5BBB15959C80C00CE1A"
        "FC924DD99651CE1136B102A919CCB0D04B111D9705324A66E27BAC768AFC85B6"
        "792CB0E0CC2CBB3E34016102D3C1E20B138193E1C273DC081007110906503D31"
        "75B14AEBDA59CD376690816E0282CD6343EF494862C40037E1540229D04048B9"
        "92B3B8A93709325E5E83E18B6902921CF90F2CA11CE7A53E580ACD77BECFEC6A"
        "08039E14E6E3C43E192DEE05B9BE02DFD39E1CCEB63A27E7F897A1EF3F77AB43"
        "94212C6C62F8D41C22C8B2165ED4F903C808A93037A509DC02B64F4F6BAFE429"
        "BA01093B4F22DE6BC009E6A1C3B3523F4CEC99316B5C5FA428C344442DA6C0D9"
        "C1DEED6329DC8A03F0996DF448B7C5D5E7735B5F43490EB0F80CEDA9361B5184"
        "904DB50E5B52EC16EF8DD8C53B8A38C4";
    static constexpr char const* kSingleCommitment =
        "02364A8C2230E2640E5F8F05F2C8931E1A5FBBE031B3B69AB9D3BC4CEE6F49BB3D";
    static constexpr char const* kAggregated =
        "0294988DF7F50D607ED7B8D194D8FC6908A2003AC2C035E04869E01270B8CF71"
        "0602B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "86740264C0644D50A1B0D9668B197A59B1C6DCE2D8A7B124B59BC5617B8A551B"
        "ECE2B103CC63AFCCC20FFA2507DDF2BE31ADE0797FE6E7308685690DEBCC028F"
        "2229C5470F31D98095465F14DEA1CF22D13E594CC5533A917A3B833D5F3216F2"
        "175E80AF54DEF7A281485999300F4DD21045A6ACE06F684089D4FE90A3C70B7B"
        "255E9B2313998F12909D5C756B6F6E5CD09EAB84C6CE0885CBD854209B04A768"
        "B3ACC54E03151A4C30383D449ED17B4A262859566F66AE6A96B255238160A7EA"
        "A3D70A72800301F3ACD54987093538E7EC3DCECEF2EA131252CF5E45408C9008"
        "61C4D62B69F403C3D4B874A6C6FB680D4D8D71228D3C47F1154E41EE80C39357"
        "9BF3ACC42EA5A103622EA8220209058A34934253D3908A496EB9BB20BD34587F"
        "5011B3B189FABC66037CA8B9763D63487A97DC91C4FDF71F1D1826959C6E30C3"
        "60A048EB371D448ADC022F0894F9416B483A6CC0D461FC85FB26E6E5F33B6082"
        "D6DCF9A354D6BE9CB3F6039592CD58904A34F970010A94896D65599A42C3E4F6"
        "2B5B0DCDDC4BD2AF3355460208CE355C71C7C4BBDC5D2A468D5FBAD27B810C74"
        "7AF43AACD6490F1CB6549505036E0D8307CB337211B2146B2B08D0A486856273"
        "73738993C0A43BCE7CC7A56D540317AF03D9E684B864FA742E3F633904E203AF"
        "4AABF02B3269BB77F57B7CE07E0703C26F45C6769F035A018B05450433AEC2D2"
        "5B1CC6C4073040F7E38F5E10C6516103214ACB553FCFEECD230697A25CE6AEFA"
        "282DF7B6C720B922539204F441E6F4CE030EF620BC55777C7FBBCE3B4A18F21B"
        "4C31B2A34E25AF6A66E8020F3740BF3E0A0371D3F285A22F808896FBEF9A2976"
        "64B55B7C8872163013E611AB55DEBE30F3DE5CC7D3A041A6F032B810964D078C"
        "B7DC7B402E3C0C43D3D251EE392A6A056BB12A302F2AF33A8703B406FDBA6DC5"
        "1A329F9CCB7DD0AA5AA45006BD5ECA401FF4";
    static constexpr char const* kAggregatedCommitment0 =
        "02C4CAE1CEEC309954F210D241516160CE7EC22DB91F1308E6BDB96740D77516AE";
    static constexpr char const* kAggregatedCommitment1 =
        "03898B88DAA25A57BAEE6FD3ADEC1B31E00B374D3EA42B0C015123B05317AA1948";
    // Proofs from a cheating prover that runs the honest algorithm on a
    // witness inconsistent with the commitment: the inner-product argument
    // holds, so only check (72) and the a_R = a_L - 1 constraint reject them.
    static constexpr char const* kCheatOutOfRange =
        "02E73ED8335E920478B44D72A213F4126A02381C70C1846A319F766EB2FAB740"
        "3C023D57AB000F1D00109BA5D94D79EB26214BBF65083C9BE92B7D30B5502F0A"
        "E38D03C1A1B5423C3F87DC8B631EA318E8D4A441993A0416B7E1E5D6FE58B4E5"
        "DAB34503CF118B745C58D295149AD182D5564C1C631A72E19BFE5F2B66961D92"
        "06FCD3E2C108FA4E1DAE219432A19A248717266302E46BCF7479862D8147D611"
        "1D8E857E9DFA8EACEA69236C6C20C036A74277B47335C49E8928BCE3E646F641"
        "D61E06CA822A7E854348B71DADD516822BB0BE9F756BC95EBC5005A46D35F4DF"
        "E5287B560267C10172CBEAB7A3439297CE25F9DA7B3F9B651EEE7C0E36F0ABFD"
        "0D3C413DEF02D431066C77AE99347A1E08365B4B9D3FAC3E6F30EEF935B0687F"
        "4757AD3452F903A0A6956539E6D8F3B5FB3FAC0A0BC3BEEA9FD2EEA11E0EF356"
        "337382A2D403A603CA1189778D162203EF97A229A38E874FEA4CAF4212946267"
        "FD98D41E7A5E4D3D0245700B1E037339137A4EE50809F933F493A1F8FA2701BD"
        "BF6178554BFF8FDE0F0304D4611F916CBAB78F7DD3161CC135754C0169684BAB"
        "3FA334D0701631D31EE00291ABAA6B0E5E7B90D3B57606E40FF77E00549A3D6A"
        "116331CD0F22D62456993603B7C46810DC16E7A7C98873E45D339C735E0EA118"
        "4B9770BBA324802CD85A3F6B02483AA84E72A1B895B0B5F07E051532444747B7"
        "73FA87AC207A51332C0CAE5C04036613410B05E620060F648C86BC4746053847"
        "09EAB7C34A9A04BA6B15849CA96B02EBE52445E77C668315FCECE81FF4DFA0F6"
        "196BB1B2A72CD779C74C527478133A02135493E39A3FEBB086CB9B3211D33481"
        "4D4C924572EE774CEF0253893F25EFC774A001C9EB448100F45CE5835A7BFE34"
        "079BEBCF83B07A985A158A80F046AC56705B0B0D7374855571E99C800961BA31"
        "CCC4A96933555371E98A73B13479D1FA";
    static constexpr char const* kCheatOutOfRangeCommitment0 =
        "03E6832B9D7E4041457C35FF32EA949D0F5604E70CB06652694DBEF65BA993F29A";
    static constexpr char const* kCheatNegative =
        "02B773AA76597E2D3B8F8CB5CF6385FBA2150C65E93E63D7BFAEBEA65C6F39B9"
        "06023D57AB000F1D00109BA5D94D79EB26214BBF65083C9BE92B7D30B5502F0A"
        "E38D0286A16D610A28F3148E57B255DDFB64DE3E0473AAC4A3B7390965C74A03"
        "A2F8AE03A5A56F3BA5A7C1E7CD8FE6FD2563B416422307EF0DFF04D38439297B"
        "70B32844F3F6DCC89591166C198C9351EA2F2E90CAA4AB91D864B01D4AFADD91"
        "525197A75ADB4C2CA669E0D281C60E0ABE916C98D83B4BA71CFFCC6ACC9EF1F9"
        "533225F5D2BA27E8E36A7D40DA23704EFCA1023844BD7F8B6BBEFDFD4C4B030F"
        "ABAE947B0273948977CACA914DB6D87BCFA144C35B45A4F8674BCB1A7F2CBA8F"
        "18D78C988002DC5864A34FA6D350924B0DDF8AB8721FB61D9AC033498C630359"
        "2305E2B1757A030C15061FC82179675315159971C78C2EF237836F5483A6E5AC"
        "4ECE25D511D0B6033FE1878158967FE29090DA12D96292F47DDC8D8FADDA3B2E"
        "DC9AEE1AC23BD69F031420D970A15D8C725912402156043951A40142FD2F3419"
        "3087ACB6AC06AF65BC024A2F14A9CEC7A18D7B848F06AE146F2AAE96D65F636B"
        "BEC9AA58FA6D74E62A9D02C1DCFB839448F052EC22EE55E6249BE3723184FA68"
        "6424EBD133D3193F9EE19802D5C2BD913ECDF26EE20CA883A857EC3D63B28AD2"
        "B5D10F0FDFDC6F2EAC313E0903A2E3EEAB68D3651DD41E1EDD382E0D9188907C"
        "123B198505CB28BA2273ABA23F0233D14285E3192642E90D62373C3C7F6FBCFB"
        "F891220D87B8827D924264709BB50249810FA59F7893D8C03DF1F086B115C235"
        "1E2343937FDC4CCE2B62B1A5818C9F02D6618112C0A4B5320B60C6A7EA24A852"
        "92DE6E0C1D3F0E0B961A08059C53E1DF73DA477E6B3854B7C78448C6472FD16E"
        "BA2C4D74F03828572324214CFEDC19E78CED1EAD62A63B6B2A42172289F0AAB4"
        "D4369911B5504C2BEC14E132AF20B67C";
    static constexpr char const* kCheatNegativeCommitment0 =
        "02C06C9669F5E8B7D505A7975CE1B9461B24D2C8D95F8F1DE70AD603ED203CE142";
    static constexpr char const* kCheatNonBinary =
        "025A8F07CE188A9243E24DA39DD0BF6E29D4EEB4AF9E1BCB5D8222308290F471"
        "A7023D57AB000F1D00109BA5D94D79EB26214BBF65083C9BE92B7D30B5502F0A"
        "E38D0209F491E25BC8E53851C7E1E9C31A63A0B625861C5AD3BCE143097124F8"
        "1702AF021F8C55927B15980E8212B53EB3F5E0A1F6D4F955B6759463A82B20BD"
        "643020EBC3B5A304DBD0946AB2427AD5500CD2E62A1C2949B8F7BB1527028137"
        "B594CDD740A7079EA11A997563E4DA0348225310787BC4BA1ED2A74C098B3E09"
        "1FEF82551150FB08B4BB4B2BBEE1746FACF8791D209E8474E4E05F49726C30D4"
        "78800228029A51DB768AA871D6BEF4C5E4F82CF5983158C08DC6575BB48A90F3"
        "95E333B7CA03B8AD42482A80FBBAC9ECC0C7C3E6DB4217D0250D41747E657C28"
        "434291914BC1038D95589CB92C4CA09CF40FE0340B0E56EA2CBE379F80A13861"
        "798AAA537230BA032FCF9253508595E477E0D3DAB531C1B5CD35A30392E5270D"
        "B96809D08DD284BD03F1402A3CDA00F857223DECE1180B5D62FD3475D174714E"
        "9DD7677B1D3FE4B79603576C9D4E404220F8CF9E3E9DDE524DAAD6C7343C0733"
        "0FBF424A4722617779EC0322B7F81248BB7A077872D57E551DC87FB39B74AE3C"
        "A08AAB11D41629FC4C4309021F8EE14203F1FB7695F7D455083A167BF7365EC7"
        "A1CBC8BC2D758E7F22BCC38403716C1E29A7F4CDB7833ECD984C701E64EAE8DB"
        "DB6B001C13F025BC52706E83A803D5F0D1E56998FD880BFD93C3E861BAF9FB79"
        "12006CE36D1EC2F4EF70BBEC0D82039F036D51652F36699244DC63D00E2C7FE8"
        "05DB47DE5B4CACB5DFD9B8CDE981AB03C4311EB7A371734064BACED2ACE2EE78"
        "B00F3B1197A9917032DA244801A78EA381972774E2163367B83C89C91BB6B898"
        "6C4449194F41A8683DF4ED18428D26160FEBE3A34BDAFBBCD04824C816C902D3"
        "230CE43CDF281D327A1288FDA998BEA8";
    static constexpr char const* kCheatNonBinaryCommitment0 =
        "037737042326111530E6B8EA80ACE1240DCE491579CA690A123B514B6C045917F5";
    static constexpr char const* kCheatSecondOutOfRange =
        "0212648ED57F39AB4EBEFEF4CF5829050CF720B353EF7E8CAEC8CABEC601F9BD"
        "6702B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "8674029E1F70ADF1E2AB0AEDA00E291D84043CA61A8F132CCB225B721F75A81E"
        "3D15E303C31CE47216E346758FB4FCDCE8273A3DDB444EC0C93B03E5A23F7E79"
        "61AB4C024CCA96844BF569BFF09340F16C9F1C393AFC6D1C0EA912D6F2D457E0"
        "F41742B91FBD86D4340CF779D8B4F96B44D5A373E802FB7AAF3957CBFD8571C1"
        "DF90848FAFBE2825A0A0843350A8DAFA0BE61EA691F5DFF93E2D15530652D8F2"
        "41C11C86025CDA90B8BE8BB73D370A276284ECEF21719B343108AF9090734564"
        "609578006303F09506E56AE1FA83AE54E0422119CEA374123CF27A01E282229C"
        "01939088F4D8022AAB51BF5668D4378618FE283426F167D70B628A3AED2703C1"
        "6DBE34C31629D803820A531F9FE56E9A92F96E647A1CDF853F322B2FDA711382"
        "35456024B179F3D603B7AE550DF5550CA330FFDB1A092EB3620965C117822980"
        "9D55883D79893A4A10037FF01B3B864D3DF87A0B1C110224FD335EDBFA48FFFB"
        "A1EF27F70104EAA3E5490266C50D696D804A4856A3C6E0A33142A86BEAA93CEA"
        "F70E8123EAE08236A659360339C694A0A6DFA16538B3846115F1258C9C79FB8F"
        "FD2BA8CFA96DCC273A9E8AB502285C4DC39FE8E981D8E97D5D3B90BBDC13D18C"
        "F35AD502BE639EF92EACCDE3C903E82743FD162107590B9B7FDF76A16BAF659D"
        "32F0A9BFB82AE311CC6D75B1A69D0272FBFDA59119B795D435834154F284C1EE"
        "484336727A35D5719569726261414F03BD29C851F7B1F9E4465B173BDC890722"
        "5218FC894147C01C7CB0AA361E69327D037A0564C626719E20903BC93279C00E"
        "807CFEC7C029E17414CD76B25D90482CDF02EF36BB84B4369F869CDDD484CC82"
        "14BBB71702DACC0B16769AC446E0E2BB6998F3F469234A32D6518D859D64B20F"
        "09F660457E9324C56F2E86A521447ED80918273761B466564244D9F14C5E581A"
        "3D4BEA7525B9BAE4A2900968EFAB1A067C3B";
    static constexpr char const* kCheatSecondOutOfRangeCommitment0 =
        "02C4CAE1CEEC309954F210D241516160CE7EC22DB91F1308E6BDB96740D77516AE";
    static constexpr char const* kCheatSecondOutOfRangeCommitment1 =
        "03D8922A25EFF188B070D11FBCB6AFEC2B1826C2FE0D05F10D669C735FD8D675A3";
    // Aggregated cheats exactly at the boundary, in either position: 2^64
    // committed with the bits of 0 proven, and -1 (n - 1) committed with the
    // bits of 2^64 - 1 proven. The other value is honest.
    static constexpr char const* kCheatSecondTwoTo64 =
        "03E1B0AADAA6AB111760DC6C17E3BDD867E3DE41F2D8DB7947A9042A6C784B6B"
        "4F02B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "8674024591B26BDB4267BF7ADC5151844FDC42CC03A6EAFD0362F777C7645BF2"
        "EBF1AE038FFF0CEB55DD5FCFDE7C362AA9CA62261B72D9A0D17CCA65617A6947"
        "49FA68CF44A8FFFF4604D496970DF6526CEAD53A82A765DA6F81F27BFFF4FC76"
        "AAF8FA828DB71D663D6E043E0C5A21AE3DF590BA7234FD98C1A88522BEFB2CC8"
        "B9059312D4E729E67331A336542F39498793390EC71F270D818BFE7235A5CF87"
        "B982AFE003116CE9ADF47E65EAD9491D29A6CE1FE6CC4D0778A69FFA1ED7BB4B"
        "35A36A3B2F024EE6011FA6E07722B6580F5BB01D26A85647FEB8B24BF191FB3F"
        "F2A70247887C02EAFCA25EA982FCAE1E5723DA5A97FA5B08BBA50205051D2FC1"
        "A88447C75EAF3502219CF3E68B36936FF296DEA1F83366EC53E0E4151D2A37C1"
        "2C58E321882D3AF7029D85C6B46B1EAE3D4E0C59A6F08CEDD1B9EF736A5C6B3A"
        "38735EA93F8CDE341A037DADAE00696A2D4202E7C0BC356F4CAD7E9277791C10"
        "E04E3F53E51B6C108A1B021A197EC393A35E16CB948E0E223F273CE83A9D6F3B"
        "B9392B2327A2AC70DF4D9303801E59C2FBA8A57CDB3462C6A4007AA84846FBB3"
        "82863DAB2DCF72BB97F84A8E03D8040490E36E834CE5F184C8D21B768E0F8429"
        "DC7F8C816B9DAF9FA2B5768BCC0230A25C07D299D388A4FABE4BE9CED3DBA189"
        "2F7A57147955A4CA233AB871658B03E13B136BABC8A50F92FE9FC1E345E2F73E"
        "D6217C7B5427F2CCEF24F6F5046298025CFCCA8AED2761DD25475661935C0669"
        "375B108555CA736597ADF433BA1A998B02830E69202E631DEA0A49910AB3B218"
        "917E1479706E660D9BE8FB7BF7C1D5DEC003DAAAB60E6930F4FF50A13D5AC2FA"
        "88E88CB972CF9F110B0F9CF5E59F3C170A34A60F2AA1FE28652EC992B02AD7A2"
        "F65C331F11D6AB186C363FE799F47E40EDB9C0736189A51583DC7242B63A070B"
        "62D7D7DC3F4B55650A2EB8211BCCE24DC2E6";
    static constexpr char const* kCheatSecondTwoTo64Commitment0 =
        "02C4CAE1CEEC309954F210D241516160CE7EC22DB91F1308E6BDB96740D77516AE";
    static constexpr char const* kCheatSecondTwoTo64Commitment1 =
        "0254843129A11ECCAB2736D49C9001FBB6B34174E3564458907D38AFF4CBDB06C4";
    static constexpr char const* kCheatSecondMinusOne =
        "0294988DF7F50D607ED7B8D194D8FC6908A2003AC2C035E04869E01270B8CF71"
        "0602B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "867402514E311AA90ED695CA95EFBB97C480B69107AD6DFD497B3343BD12F04B"
        "378E5B0239E0376F33F1416EFFEA9093EE0E6998A0B042C28F4909025952787A"
        "F52CF44B4F87D71235C49EB0B30653F17F5675E65011E9DF35F8E6F16481304C"
        "D48A9FD17897438FE53E6DED51EF6E27028BF256C581280B4DD3819DAC380198"
        "9986819008F1D45D2D9DD689D32915F8AF654748D163ACE3D423FDAC8DC34ADD"
        "9A59CE8802F10970FC0F19015843BB9F3FFC716596403E11F4E82662E38CD061"
        "2FFC025FF903725B5B57E40BC84B5EF33620CE57803EDD6B78226388ACF4BA07"
        "6464E710CEEF0312CF6AC4465520E1CDFCD65ACE21AAA859040A120D683B04FC"
        "9AEA693AFBC41903A1CFE341F7085F7E7FBF92EC909CE7CDE36D935EDB62FA6D"
        "B5A698A30C8067C4027D80A81390D24FFBA0E439F31795D817B5DDF8D2EAB13D"
        "FB1386246C4EF5489A02FE7E9A8570DDE1DC82D8385433781F4D23DD1ECE32A7"
        "E2460E11B31772B633A7027F9AFE3EBEBFF8576AE7E57EA6A9AFDCE8903020D1"
        "1048CAE9CCD2FED9C18D33034CF15FC369AE4A51A72300B41041BC01810BE34B"
        "A6BBE0148FC259494B971AA10355FA7084E56F48B99509DA0D60B3B80CB08DA5"
        "B2F2A098634A5C462EC9528F7E036934DF382DE7D3CC8A140887146EC7F44F61"
        "09D6879F203660B0E3385D08DCA003FE88296BD996CB1705808A13DBFA67608C"
        "5B665ACD6EC901EE6D0A2A6EA2CEBB0252149F500013563523338429438F9EAF"
        "4A273E0C5B9A7E68330C55CAE1FA71F202DB3446B0901C3814479E94E3EA1F59"
        "41BAFE0C28F3BB372FC68A1D1541CEAB6B027233125FA734DFC6D5BCF41B6B67"
        "008E49B5EA3D17E6D18F90D7BB54C48B92B4E05E871215FAA92D58C45DA61BDE"
        "246EBDDF30F8875CD60D02A1A0AC9B488E956B6B491DCA54A002E3EBD6857442"
        "8D0FB1B70F6FAFB058F50AC8767E7CACA729";
    static constexpr char const* kCheatSecondMinusOneCommitment0 =
        "02C4CAE1CEEC309954F210D241516160CE7EC22DB91F1308E6BDB96740D77516AE";
    static constexpr char const* kCheatSecondMinusOneCommitment1 =
        "0268E83AF44D3633445E707E9C653EA387B7BA49DE0E18605373E0753E674A4EB3";
    static constexpr char const* kCheatFirstTwoTo64 =
        "02EEF9273DA13189A95015CAB356B53AAACADE89D2AD7ABAD785CB09091300CD"
        "DC02B40C510D02ED6F3CA916AA4BE6DBFB71E6E2622A583960FD25BE16A0AE72"
        "867403512B7DB5A58D126E7863D636E1A89304BE4A8AD1007327BEA2DE4A07C8"
        "C67A0F03B3D3DE43338F811339C4FEB37C4F6B67A40657598FDBD90A83089D88"
        "61BCA3CE958C6A6ACA1209B91380126C964FE9CBF173BD33C61E1B24764FDD9B"
        "3BF2BCE3511B2B61544D92152C2E185686CB053FB40D1353BE9984D1DEFB2BA4"
        "105812BF966C36FF9669A174B3B776C3FD001935D661590111E895E22033A96E"
        "CF6699DF02B43910DEEED9228CC86AA19B15DDF9D27C83B27FE5DA1A8E37A7C2"
        "18D59714990351FB1D3E8BFCC1AC1D583645742CBB9E3CBEAC9D64447AFB2A0C"
        "109DFC9A4357025CAB10BE378C9C3BDFF5A91DCBD834310689CF344ED8C2B2E0"
        "C9604CDF3957A103B21B5EF72475AB380801B38F2F0C27FC9C21196396009DA1"
        "34D288CA77FB399503CB54993F19A11304970D94335C5EFB50336597728A84DA"
        "AB77ABBFDA59CA9F96032C3C1578754AA6F240E482987205DCAD4C106E11C7FE"
        "8158D4DCE107427F0D2602D4EC5E8E415ECD6B3794E6174D741D4F2C8D522E4C"
        "C799E7F73505F58EA5F10E03B5F51506CC9A54CE434D907D2B22277F49DD6026"
        "069A217CF8E243032245D671021556AC572EB7DACE22114D908AF3D61B1A7582"
        "F71750F7607FB747F057726F6302254DA2EA29C0A949D8C8F7F600B6C0154DAF"
        "DBDA81F872120C745AB959775EBA036AC5503ECDCE8020B3D16E120F16F8DCF6"
        "0B0AB3931E7EDD72A80B30EA00E61802D4C63E6CEDB9CEC1903BE2D19642D302"
        "F0A0D6F0A3C6C1D40355438463CABD10026D3E5E612BFA8F6ED54F8E13B8DA10"
        "EF6B220AC4F4E7037E82F1F76D1FBC1D5E02AE293D504673647BB6781F55C605"
        "D105E0596F6B448B63EF1217AEE931412FA552709C0E5A07CC1AC65C7D8C064D"
        "B32E05CCF23F3613DFB387D987F8678BC354F2A9ABA80AD121CEDFDC4A2A257B"
        "E5498756F2E48CDAE3C9F80DE34816595BCD";
    static constexpr char const* kCheatFirstTwoTo64Commitment0 =
        "03C568F8F14135F8454839D12A6A207061BB61B8044D5F0A512E8CCB167BD32A98";
    static constexpr char const* kCheatFirstTwoTo64Commitment1 =
        "03898B88DAA25A57BAEE6FD3ADEC1B31E00B374D3EA42B0C015123B05317AA1948";
    static constexpr char const* kOrder =
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

    static constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();

    static Scalar
    s(std::uint64_t v)
    {
        return Scalar::fromUint64(v);
    }

    static Blob
    hex(std::string const& h)
    {
        auto const b = strUnHex(h);
        if (!b)
            Throw<std::runtime_error>("bad hex");
        return *b;
    }

    static std::string
    toHex(Point const& p)
    {
        auto const b = p.bytes();
        return b ? strHex(*b) : std::string{};
    }

    static uint256
    context()
    {
        uint256 c;
        std::fill(c.begin(), c.end(), 0x42);
        return c;
    }

    bool
    verify(std::vector<Point> const& v, Slice proof, uint256 const& ctx = context())
    {
        return verifyRange(v, proof, ctx);
    }

    template <class F>
    bool
    throwsInvalid(F const& f)
    {
        try
        {
            f();
        }
        catch (std::invalid_argument const&)
        {
            return true;
        }
        return false;
    }

    void
    testReferenceVectors()
    {
        testcase("Reference vectors");

        auto const single = hex(kSingle);
        std::vector<Point> const v1{pedersenCommit(s(1000), s(0x1234))};
        BEAST_EXPECT(toHex(v1[0]) == kSingleCommitment);
        BEAST_EXPECT(single.size() == kSingleRangeProofLength);
        BEAST_EXPECT(verify(v1, makeSlice(single)));

        auto const aggregated = hex(kAggregated);
        std::vector<Point> const v2{
            pedersenCommit(s(250), s(0x1234)), pedersenCommit(s(kMax), s(0x5678))};
        BEAST_EXPECT(toHex(v2[0]) == kAggregatedCommitment0);
        BEAST_EXPECT(toHex(v2[1]) == kAggregatedCommitment1);
        BEAST_EXPECT(aggregated.size() == kAggregatedRangeProofLength);
        BEAST_EXPECT(verify(v2, makeSlice(aggregated)));
    }

    void
    testCompleteness()
    {
        testcase("Completeness");

        auto const ctx = context();
        for (std::uint64_t const v :
             {std::uint64_t{0},
              std::uint64_t{1},
              std::uint64_t{1} << 32,
              std::uint64_t{0x7FFFFFFFFFFFFFFF},
              kMax})
        {
            auto const gamma = Scalar::random();
            std::vector<Scalar> const values{s(v)};
            std::vector<Scalar> const blindings{gamma};
            auto const proof = proveRange(values, blindings, ctx);
            BEAST_EXPECT(proof.size() == kSingleRangeProofLength);
            BEAST_EXPECTS(verify({pedersenCommit(s(v), gamma)}, proof), std::to_string(v));
        }

        // Both boundaries in both positions.
        for (auto const& [a, b] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
                 {0, 0},
                 {0, kMax},
                 {kMax, 0},
                 {kMax, kMax},
                 {1, kMax},
                 {kMax - 1, 1},
                 {123456789, 987654321}})
        {
            std::vector<Scalar> const blindings{Scalar::random(), Scalar::random()};
            std::vector<Scalar> const values{s(a), s(b)};
            auto const proof = proveRange(values, blindings, ctx);
            BEAST_EXPECT(proof.size() == kAggregatedRangeProofLength);
            BEAST_EXPECT(verify(
                {pedersenCommit(s(a), blindings[0]), pedersenCommit(s(b), blindings[1])}, proof));
        }
    }

    void
    testSoundness()
    {
        testcase("Soundness");

        auto const ctx = context();
        auto const single = hex(kSingle);
        auto const v1 = pedersenCommit(s(1000), s(0x1234));
        auto const g = Point::generator();
        auto const h = pedersenGenerator();

        // The proof is bound to the exact commitment and context.
        BEAST_EXPECT(!verify({v1 + g}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1 - g}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1 + h}, makeSlice(single)));
        BEAST_EXPECT(!verify({Point{}}, makeSlice(single)));
        uint256 otherCtx = ctx;
        otherCtx.data()[0] ^= 1;
        BEAST_EXPECT(!verify({v1}, makeSlice(single), otherCtx));

        // A value of 1000 + 2^64 has the same low 64 bits but is out of range.
        auto const twoTo64 = s(kMax) + s(1);
        BEAST_EXPECT(!verify({v1 + twoTo64 * g}, makeSlice(single)));
        // Nor does the proof cover "negative" values.
        BEAST_EXPECT(!verify({pedersenCommit(-s(1000), s(0x1234))}, makeSlice(single)));

        // The commitment count must match the proof.
        BEAST_EXPECT(!verify({}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1, v1}, makeSlice(single)));
        BEAST_EXPECT(!verify({v1, v1, v1}, makeSlice(single)));

        auto const aggregated = hex(kAggregated);
        auto const a0 = pedersenCommit(s(250), s(0x1234));
        auto const a1 = pedersenCommit(s(kMax), s(0x5678));
        BEAST_EXPECT(!verify({a1, a0}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0, a1 + g}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0 + g, a1}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0, a1}, makeSlice(aggregated), otherCtx));

        // An identity commitment has no encoding, so no proof covers it.
        BEAST_EXPECT(!verify({Point{}, a1}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0, Point{}}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({Point{}, Point{}}, makeSlice(aggregated)));
        // Nor does it transfer to the same commitment twice, or to either
        // commitment on its own with the single-value proof length.
        BEAST_EXPECT(!verify({a0, a0}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a1, a1}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a1}, makeSlice(aggregated)));
        BEAST_EXPECT(!verify({a0}, Slice(aggregated.data(), kSingleRangeProofLength)));
        BEAST_EXPECT(!verify({a0, a1}, makeSlice(single)));
        // Binding: the proof does not carry over to the second commitment
        // shifted by 2^64 (boundary soundness is in "Cheating prover").
        BEAST_EXPECT(!verify({a0, a1 - twoTo64 * g}, makeSlice(aggregated)));

        // An honest proof of one value does not transfer to another.
        std::vector<Scalar> const values{s(7)};
        std::vector<Scalar> const blindings{s(99)};
        auto const proof = proveRange(values, blindings, ctx);
        BEAST_EXPECT(verify({pedersenCommit(s(7), s(99))}, proof));
        BEAST_EXPECT(!verify({pedersenCommit(s(8), s(99))}, proof));
        BEAST_EXPECT(!verify({pedersenCommit(s(7), s(98))}, proof));
    }

    // Every malformed variant of a valid proof over commitments v fails: a
    // flipped bit in each byte, each wrong length, zero and non-canonical
    // scalars at every scalar position, and invalid or substituted points at
    // every point position.
    void
    expectMalformedRejected(Blob const& proof, std::vector<Point> const& v)
    {
        auto const label = [&](char const* what, std::size_t pos) {
            return "m=" + std::to_string(v.size()) + " " + what + " at " + std::to_string(pos);
        };
        if (!BEAST_EXPECT(verify(v, makeSlice(proof))))
            return;

        for (std::size_t i = 0; i < proof.size(); ++i)
        {
            Blob bad = proof;
            bad[i] ^= 0x01;
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("flip", i));
        }

        BEAST_EXPECT(!verify(v, Slice{}));
        BEAST_EXPECT(!verify(v, Slice(proof.data(), proof.size() - 1)));
        Blob longer = proof;
        longer.push_back(0);
        BEAST_EXPECT(!verify(v, makeSlice(longer)));

        // Points: A, S, T1, T2, then L_j, R_j for each of the k rounds.
        std::size_t const k = (proof.size() - 5 * kScalarLength) / kEcPointLength / 2 - 2;
        std::size_t const lrAt = 4 * kEcPointLength + 3 * kScalarLength;
        std::vector<std::size_t> pointsAt;
        for (std::size_t i = 0; i < 4; ++i)
            pointsAt.push_back(i * kEcPointLength);
        for (std::size_t j = 0; j < 2 * k; ++j)
            pointsAt.push_back(lrAt + j * kEcPointLength);
        BEAST_EXPECT(pointsAt.back() + kEcPointLength + 2 * kScalarLength == proof.size());

        auto const generator = *Point::generator().bytes();
        auto const fieldPrime =
            hex("02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
        for (auto const pos : pointsAt)
        {
            Blob bad = proof;
            bad[pos] = 0x04;
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("uncompressed prefix", pos));
            bad[pos] = 0x00;
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("zero prefix", pos));
            std::copy(fieldPrime.begin(), fieldPrime.end(), bad.begin() + pos);
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("x = p", pos));
            std::copy(generator.begin(), generator.end(), bad.begin() + pos);
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("G substituted", pos));
        }

        // Scalars: tau_x, mu, t_hat, then a and b.
        std::size_t const scalarsAt = 4 * kEcPointLength;
        std::size_t const tailAt = proof.size() - 2 * kScalarLength;
        auto const order = hex(kOrder);
        for (std::size_t const pos :
             {scalarsAt,
              scalarsAt + kScalarLength,
              scalarsAt + 2 * kScalarLength,
              tailAt,
              tailAt + kScalarLength})
        {
            Blob bad = proof;
            std::fill(bad.begin() + pos, bad.begin() + pos + kScalarLength, 0);
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("zero scalar", pos));
            std::copy(order.begin(), order.end(), bad.begin() + pos);
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("scalar n", pos));
            std::fill(bad.begin() + pos, bad.begin() + pos + kScalarLength, 0xFF);
            BEAST_EXPECTS(!verify(v, makeSlice(bad)), label("scalar 2^256 - 1", pos));
        }
    }

    void
    testTampering()
    {
        testcase("Tampering");

        expectMalformedRejected(hex(kSingle), {pedersenCommit(s(1000), s(0x1234))});
        expectMalformedRejected(
            hex(kAggregated),
            {pedersenCommit(s(250), s(0x1234)), pedersenCommit(s(kMax), s(0x5678))});

        // Each proof length only fits its own commitment count.
        BEAST_EXPECT(!verify({pedersenCommit(s(1000), s(0x1234))}, makeSlice(hex(kAggregated))));
        BEAST_EXPECT(!verify(
            {pedersenCommit(s(250), s(0x1234)), pedersenCommit(s(kMax), s(0x5678))},
            makeSlice(hex(kSingle))));
    }

    void
    testProverArguments()
    {
        testcase("Prover arguments");

        auto const ctx = context();
        std::vector<Scalar> const none;
        std::vector<Scalar> const noBlind;
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(none, noBlind, ctx); }));
        std::vector<Scalar> const three{s(1), s(2), s(3)};
        std::vector<Scalar> const threeBlind{s(1), s(2), s(3)};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(three, threeBlind, ctx); }));
        std::vector<Scalar> const two{s(1), s(2)};
        std::vector<Scalar> const oneBlind{s(1)};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(two, oneBlind, ctx); }));
        std::vector<Scalar> const zero{Scalar{}};
        std::vector<Scalar> const zeroBlind{Scalar{}};
        BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(zero, zeroBlind, ctx); }));

        // An unblinded commitment is not hiding, so no blinding may be zero.
        {
            std::vector<Scalar> const one{s(7)};
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(one, zeroBlind, ctx); }));
            std::vector<Scalar> const pair{s(7), s(8)};
            std::vector<Scalar> const firstZero{Scalar{}, s(5)};
            std::vector<Scalar> const secondZero{s(5), Scalar{}};
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(pair, firstZero, ctx); }));
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(pair, secondZero, ctx); }));
        }

        // The value 0 in every position still proves: its masked bits start
        // from a blinded offset.
        {
            std::vector<Scalar> const zeros{Scalar{}, Scalar{}};
            std::vector<Scalar> const blindings{s(5), s(6)};
            auto const proof = proveRange(zeros, blindings, ctx);
            BEAST_EXPECT(verify({pedersenCommit(Scalar{}, s(5)), pedersenCommit(Scalar{}, s(6))}, proof));
        }

        // Values of 2^64 and above have no proof, in either position.
        auto const twoTo64 = s(kMax) + s(1);
        auto const top = -s(1);
        for (auto const& big : {twoTo64, top})
        {
            std::vector<Scalar> const one{big};
            std::vector<Scalar> const oneBlinding{s(5)};
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(one, oneBlinding, ctx); }));
            std::vector<Scalar> const first{big, s(1)};
            std::vector<Scalar> const second{s(1), big};
            std::vector<Scalar> const twoBlindings{s(5), s(6)};
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(first, twoBlindings, ctx); }));
            BEAST_EXPECT(throwsInvalid([&] { (void)proveRange(second, twoBlindings, ctx); }));
        }
    }

    void
    testCheatingProver()
    {
        testcase("Cheating prover");

        auto const point = [&](std::string const& h) {
            return *Point::fromBytes(makeSlice(hex(h)));
        };

        // 1000 + 2^64 committed, bits of 1000 proven.
        BEAST_EXPECT(
            !verify({point(kCheatOutOfRangeCommitment0)}, makeSlice(hex(kCheatOutOfRange))));
        // -1 committed, bits of 2^64 - 1 proven.
        BEAST_EXPECT(!verify({point(kCheatNegativeCommitment0)}, makeSlice(hex(kCheatNegative))));
        // A non-binary digit: a_L[0] = 2 with 1002 committed.
        BEAST_EXPECT(!verify({point(kCheatNonBinaryCommitment0)}, makeSlice(hex(kCheatNonBinary))));
        // Only the second aggregated value is out of range.
        BEAST_EXPECT(!verify(
            {point(kCheatSecondOutOfRangeCommitment0), point(kCheatSecondOutOfRangeCommitment1)},
            makeSlice(hex(kCheatSecondOutOfRange))));
        BEAST_EXPECT(pedersenCommit(s(250), s(0x1234)) == point(kCheatSecondOutOfRangeCommitment0));

        // Exactly 2^64 or -1 in either aggregated position.
        auto const twoTo64 = s(kMax) + s(1);
        BEAST_EXPECT(
            point(kCheatSecondTwoTo64Commitment0) == pedersenCommit(s(250), s(0x1234)) &&
            point(kCheatSecondTwoTo64Commitment1) == pedersenCommit(twoTo64, s(0x5678)));
        BEAST_EXPECT(!verify(
            {point(kCheatSecondTwoTo64Commitment0), point(kCheatSecondTwoTo64Commitment1)},
            makeSlice(hex(kCheatSecondTwoTo64))));
        BEAST_EXPECT(
            point(kCheatSecondMinusOneCommitment0) == pedersenCommit(s(250), s(0x1234)) &&
            point(kCheatSecondMinusOneCommitment1) == pedersenCommit(-s(1), s(0x5678)));
        BEAST_EXPECT(!verify(
            {point(kCheatSecondMinusOneCommitment0), point(kCheatSecondMinusOneCommitment1)},
            makeSlice(hex(kCheatSecondMinusOne))));
        BEAST_EXPECT(
            point(kCheatFirstTwoTo64Commitment0) == pedersenCommit(twoTo64, s(0x1234)) &&
            point(kCheatFirstTwoTo64Commitment1) == pedersenCommit(s(kMax), s(0x5678)));
        BEAST_EXPECT(!verify(
            {point(kCheatFirstTwoTo64Commitment0), point(kCheatFirstTwoTo64Commitment1)},
            makeSlice(hex(kCheatFirstTwoTo64))));
    }

public:
    void
    run() override
    {
        testReferenceVectors();
        testCompleteness();
        testSoundness();
        testTampering();
        testCheatingProver();
        testProverArguments();
    }
};

BEAST_DEFINE_TESTSUITE(Bulletproof, protocol, xrpl);

}  // namespace xrpl::confidential
